package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
	"github.com/prometheus/client_golang/prometheus"
)

// Authenticator authenticates a user against an LDAP directory
type Authenticator interface {
	Authenticate(username, password string) (*ldap.Entry, error)
}

// Client represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type Client struct {
	BaseDN             string
	LdapServer         string
	LdapPort           uint
	UseInsecure        bool
	UserLoginAttribute string
	SearchUserDN       string
	SearchUserPassword string
	TLSConfig          *tls.Config
}

var (
	ldapConnectionError = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_ldap_connection_error",
			Help: "Total number of LDAP connection errors.",
		},
	)
	ldapBindingError = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_ldap_binding_error",
			Help: "Total number of LDAP binding errors.",
		},
	)
	userSearchFailed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_user_search_failed",
			Help: "Total number of LDAP user search failures.",
		},
	)
	noUserFound = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_no_user_found",
			Help: "Total number of times user was not found in LDAP.",
		},
	)
	multipleUsersFound = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_multiple_user_found",
			Help: "Total number of times multiple user(s) were found in LDAP.",
		},
	)
	invalidUserCredentials = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubernetes_ldap_invalid_credentials_error",
			Help: "Total number of times invalid user credentials were used.",
		},
	)
)

//RegisterLDAPClientMetrics registers the metrics for the token generation
func RegisterLDAPClientMetrics() {
	prometheus.MustRegister(ldapConnectionError)
	prometheus.MustRegister(ldapBindingError)
	prometheus.MustRegister(userSearchFailed)
	prometheus.MustRegister(noUserFound)
	prometheus.MustRegister(multipleUsersFound)
	prometheus.MustRegister(invalidUserCredentials)
}

// Authenticate a user against the LDAP directory. Returns an LDAP entry if password
// is valid, otherwise returns an error.
func (c *Client) Authenticate(username, password string) (*ldap.Entry, error) {
	conn, err := c.dial()
	if err != nil {
		ldapConnectionError.Inc()
		return nil, fmt.Errorf("Error opening LDAP connection: %v", err)
	}
	defer conn.Close()

	// Bind user to perform the search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(c.SearchUserDN, c.SearchUserPassword)
	} else {
		err = conn.Bind(username, password)
	}

	if err != nil {
		ldapBindingError.Inc()
		return nil, fmt.Errorf("Error binding user to LDAP server: %v", err)
	}

	req := c.newUserSearchRequest(username)

	// Do a search to ensure the user exists within the BaseDN scope
	res, err := conn.Search(req)
	if err != nil {
		userSearchFailed.Inc()
		return nil, fmt.Errorf("Error searching for user %s: %v", username, err)
	}

	switch {
	case len(res.Entries) == 0:
		noUserFound.Inc()
		return nil, fmt.Errorf("No result for the search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		multipleUsersFound.Inc()
		return nil, fmt.Errorf("Multiple entries found for the search filter '%s': %+v", req.Filter, res.Entries)
	}

	// Now that we know the user exists within the BaseDN scope
	// let's do user bind to check credentials using the full DN instead of
	// the attribute used for search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(res.Entries[0].DN, password)
		if err != nil {
			invalidUserCredentials.Inc()
			return nil, fmt.Errorf("Error binding user %s, invalid credentials: %v", username, err)
		}
	}

	// Single user entry found
	return res.Entries[0], nil
}

// Create a new TCP connection to the LDAP server
func (c *Client) dial() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", c.LdapServer, c.LdapPort)

	if c.TLSConfig != nil && !c.UseInsecure {
		return ldap.DialTLS("tcp", address, c.TLSConfig)
	}

	// This will send passwords in clear text (LDAP doesn't obfuscate password in any way),
	// thus we use a flag to enable this mode
	if c.UseInsecure {
		return ldap.Dial("tcp", address)
	}

	// TLSConfig was not specified, and insecure flag not set
	return nil, errors.New("The LDAP TLS Configuration was not set.")
}

func (c *Client) newUserSearchRequest(username string) *ldap.SearchRequest {
	// TODO(abrand): sanitize
	userFilter := fmt.Sprintf("(%s=%s)", c.UserLoginAttribute, username)
	return &ldap.SearchRequest{
		BaseDN:       c.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    10, // make configurable?
		TypesOnly:    false,
		Filter:       userFilter,
	}
}
