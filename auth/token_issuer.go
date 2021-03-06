package auth

import (
	"fmt"
	"net/http"

	"encoding/json"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/proofpoint/kubernetes-ldap/client"
	"github.com/proofpoint/kubernetes-ldap/ldap"
	"github.com/proofpoint/kubernetes-ldap/token"
)

// LDAPTokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
type LDAPTokenIssuer struct {
	LDAPServer            string
	LDAPAuthenticator     ldap.Authenticator
	TokenSigner           token.Signer
	TTL                   time.Duration
	UsernameAttribute     string
	EnforceClientVersions bool
}

var (
	newTokenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_new_token_requests",
			Help: "Total number of requests to get new token.",
		},
	)
	noauthTokenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_noauth_token_requests",
			Help: "Total number of requests to get new token without username or password.",
		},
	)
	unauthTokenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_failed_ldap_auth",
			Help: "Total number of requests to get new token where ldap auth failed.",
		},
	)
	errorSigningToken = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_error_signing_tokens",
			Help: "Total number of requests where signing new token failed.",
		},
	)
	successfulTokens = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_successful_tokens_generated",
			Help: "Total number of requests where tokens were successfully issued.",
		},
	)
)

//RegisterIssueTokenMetrics registers the metrics for the token generation
func RegisterIssueTokenMetrics() {
	prometheus.MustRegister(newTokenRequests)
	prometheus.MustRegister(noauthTokenRequests)
	prometheus.MustRegister(unauthTokenRequests)
	prometheus.MustRegister(errorSigningToken)
	prometheus.MustRegister(successfulTokens)
}

func (lti *LDAPTokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	newTokenRequests.Inc()
	user, password, ok := req.BasicAuth()
	if !ok {
		noauthTokenRequests.Inc()
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	if lti.EnforceClientVersions {
		pluginVersion := req.Header.Get("x-pfpt-k8sldapctl-version")
		kubectlVersion := req.Header.Get("x-pfpt-kubectl-version")

		if pluginVersion == "" || kubectlVersion == "" {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(fmt.Sprintf("\nError: you are using an old version of k8sldapctl plugin. Please upgrade to minimum of %q", client.MinimumPluginVersion)))
			return
		}

		err := client.Validate(pluginVersion, kubectlVersion)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(fmt.Sprintf("\nError: %s", err.Error())))
			return
		}
	}

	// Authenticate the user via LDAP
	ldapEntry, err := lti.LDAPAuthenticator.Authenticate(user, password)
	if err != nil {
		unauthTokenRequests.Inc()
		glog.Errorf("Error authenticating user: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Auth was successful, create token
	token := lti.createToken(ldapEntry)

	// Sign token and return
	signedToken, err := lti.TokenSigner.Sign(token)
	if err != nil {
		errorSigningToken.Inc()
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	successfulTokens.Inc()
	if req.Header.Get("Accept") == "application/json" {
		data := map[string]interface{}{
			"token":               signedToken,
			"expirationTimestamp": token.Expiration,
		}

		jsondata, err := json.Marshal(data)
		if err != nil {
			glog.Errorf("Error marshalling json %s", err.Error())
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp.Header().Add("Content-Type", "application/json")
		resp.Write(jsondata)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *LDAPTokenIssuer) getGroupsFromMembersOf(membersOf []string) []string {
	groupsOf := []string{}
	uniqueGroups := make(map[string]struct{})

	for _, memberOf := range membersOf {
		splittedStr := strings.Split(memberOf, ",")
		for _, element := range splittedStr {
			element = strings.ToLower(element)
			if !strings.Contains(element, "cn=") {
				continue
			}

			group := strings.Replace(element, "cn=", "", -1)

			if _, ok := uniqueGroups[group]; ok {
				//this group has been considered and added already
				continue
			}

			groupsOf = append(groupsOf, group)
			uniqueGroups[group] = struct{}{}
		}
	}

	return groupsOf
}

func (lti *LDAPTokenIssuer) createToken(ldapEntry *goldap.Entry) *token.AuthToken {
	username := ldapEntry.DN
	if lti.UsernameAttribute != "" {
		username = ldapEntry.GetAttributeValue(lti.UsernameAttribute)
	}

	return &token.AuthToken{
		Username: username,
		Groups:   lti.getGroupsFromMembersOf(ldapEntry.GetAttributeValues("memberOf")),
		Assertions: map[string]string{
			"ldapServer": lti.LDAPServer,
			"userDN":     ldapEntry.DN,
		},
		Expiration: lti.getExpirationTime(),
	}
}

func (lti *LDAPTokenIssuer) getExpirationTime() int64 {
	nowMillis := time.Now().UnixNano() / int64(time.Millisecond)
	ttlMillis := int64(time.Duration(lti.TTL) / time.Millisecond)

	return nowMillis + ttlMillis
}
