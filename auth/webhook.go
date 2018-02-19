package auth

import (
	"encoding/json"
	"net/http"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/proofpoint/kubernetes-ldap/token"
)

var (
	verifyTokenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_verify_token_requests",
			Help: "Total number of requests to verify token.",
		},
	)
	invalidMethodRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_invalid_http_method_requests",
			Help: "Total number of requests to verify token which were not HTTP Post.",
		},
	)
	invalidJSONBody = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_invalid_token_request_format",
			Help: "Total number of requests to verify token with invalid verify token request format.",
		},
	)
	invalidTokenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_invalid_token",
			Help: "Total number of requests to verify token with invalid token.",
		},
	)
	successfulVerification = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_successful_verify_token_requests",
			Help: "Total number of requests where verify token request succeeded.",
		},
	)
)

//RegisterVerifyTokenMetrics registers the metrics for the token generation
func RegisterVerifyTokenMetrics() {
	prometheus.MustRegister(verifyTokenRequests)
	prometheus.MustRegister(invalidMethodRequests)
	prometheus.MustRegister(invalidTokenRequests)
	prometheus.MustRegister(invalidJSONBody)
	prometheus.MustRegister(successfulVerification)
}

// TokenWebhook responds to requests from the K8s authentication webhook
type TokenWebhook struct {
	tokenVerifier token.Verifier
}

// NewTokenWebhook returns a TokenWebhook with the given verifier
func NewTokenWebhook(verifier token.Verifier) *TokenWebhook {
	return &TokenWebhook{
		tokenVerifier: verifier,
	}
}

// ServeHTTP verifies the incoming token and sends the user's info
// back if the token is valid.
func (tw *TokenWebhook) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	verifyTokenRequests.Inc()
	if req.Method != http.MethodPost {
		invalidMethodRequests.Inc()
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	trr := &TokenReviewRequest{}
	err := json.NewDecoder(req.Body).Decode(trr)
	if err != nil {
		invalidJSONBody.Inc()
		glog.Errorf("Error unmarshalling request: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()

	// Verify token
	token, err := tw.tokenVerifier.Verify(trr.Spec.Token)
	if err != nil {
		invalidTokenRequests.Inc()
		glog.Errorf("Token is invalid: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Header().Add("Content-Type", "text/plain")
		resp.Write([]byte(err.Error()))
		return
	}

	// Token is valid.
	trr.Status = TokenReviewStatus{
		Authenticated: true,
		User: UserInfo{
			Username: token.Username,
			Groups:   token.Groups,
		},
	}

	respJSON, err := json.Marshal(trr)
	if err != nil {
		glog.Errorf("Error marshalling response: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	successfulVerification.Inc()
	resp.Header().Add("Content-Type", "application/json")
	resp.Write(respJSON)
}
