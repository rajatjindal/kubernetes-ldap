#!/bin/bash

CONFIG=$1

if [ -z "$CONFIG" ]; then
    echo
    echo "usage is $0 ABSOLUTE_PATH_TO_CONFIG_FILE"
    echo
    echo "e.g."
    echo "    $0 /root/ldap-config"
    echo
    exit -1
fi

source $CONFIG
CMD = "/root/kubernetes-ldap"
CMD = "$CMD --ldap-host $LDAP_HOST"
CMD = "$CMD --ldap-port $LDAP_PORT"
CMD = "$CMD --ldap-base-dn $LDAP_BASE_DN"
CMD = "$CMD --ldap-search-user-dn $LDAP_SEARCH_USER_DN"
CMD = "$CMD --ldap-search-user-password $LDAP_SEARCH_USER_PASSWORD"
CMD = "$CMD --tls-cert-file $TLS_CERT_FILE"
CMD = "$CMD --tls-private-key $TLS_PRIVATE_KEY"
CMD = "$CMD --ldap-user-attribute $LDAP_USER_ATTRIBUTE"

if [ ! -z "$LDAP_INSECURE" ]; then
    CMD = "$CMD --ldap-insecure"
fi

$CMD
