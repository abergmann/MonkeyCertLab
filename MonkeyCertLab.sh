#!/bin/bash

create_openssl_conf () {
	if [ -d $1 ]; then
		rm -r $1
	fi
	mkdir -p $1
	cp openssl.cnf.orig $1/openssl.cnf
	CAPWD=$(echo $PWD | sed 's/\//\\\//g')
	sed "s/CAPWD/$CAPWD/" -i $1/openssl.cnf
	sed "s/DOM/$1/g" -i $1/openssl.cnf
	sed "s/ORG/$2/g" -i $1/openssl.cnf
}

create_CA_folders () {
	mkdir -p $1/ca/private
	chmod 700 $1/ca/private
	mkdir -p $1/ca/certs
	mkdir -p $1/ca/newcerts
	echo "01" > $1/ca/serial
	touch $1/ca/index.txt
	echo "unique_subject = yes" > $1/ca/index.txt.attr
}

# create CA Root Certificate Private Key
gen_CA_cert () {
	openssl genrsa -out $1/ca/private/cakey.pem 2048
	openssl req -batch -new -x509 -days 3650 -key $1/ca/private/cakey.pem -out $1/ca/cacert.pem -config $1/openssl.cnf
}

gen_server_cert () {
	mkdir -p $1/server
	SUBJECT=`openssl x509 -noout -subject -in $1/ca/cacert.pem`
        SUBJECT=${SUBJECT#*=}
        SUBJECT="${SUBJECT%%CN*}CN=$2.$1/emailAddress=hostmaster@$1"
        SUBJECT="${SUBJECT// = /=}"
        SUBJECT="/${SUBJECT//, //}"
	#echo "${SUBJECT}"
	openssl genrsa -out $1/server/$2.key 2048
	openssl req -batch -new -subj "$SUBJECT" -key $1/server/$2.key -out $1/server/$2.req -config $1/openssl.cnf
	openssl ca -batch -name "server" -in $1/server/$2.req -out $1/server/$2.pem -config $1/openssl.cnf

}

gen_user_cert () {
	SUBJECT=`openssl x509 -noout -subject -in $1/ca/cacert.pem`
        SUBJECT=${SUBJECT#*=}
        SUBJECT="${SUBJECT%%CN*}CN=$2/emailAddress=$2@$1"
        SUBJECT="${SUBJECT// = /=}"
        SUBJECT="/${SUBJECT//, //}"
	STARTDATE=`openssl x509 -noout -startdate -in $1/ca/cacert.pem`
	STARTDATE=${STARTDATE#*=}
	STARTDATEZ=`date -u -d "$STARTDATE" +%y%m%d%H%M%SZ`
	ENDDATESEC=`date -u -d "$STARTDATE" +%s`
	ENDDATESEC2=$(($ENDDATESEC+31536000))
	ENDDATEZ=`date -u -d "1970-01-01 UTC $ENDDATESEC2 seconds" +%y%m%d%H%M%SZ`
	openssl genrsa -out $1/user/$2.key 2048
	openssl req -batch -new -subj "$SUBJECT" -key $1/user/$2.key -out $1/user/$2.req -config $1/openssl.cnf
	case $3 in
	  valid)
		STARTDATE=`date -u -d "$STARTDATE" +%y%m%d%H%M%SZ`
		openssl ca -batch -name "user" -startdate $STARTDATEZ -enddate $ENDDATEZ -in $1/user/$2.req -out $1/user/$2.pem -config $1/openssl.cnf
		;;
	  expired)
		ENDDATESEC2=$(($ENDDATESEC+1))
		ENDDATEZ=`date -u -d "1970-01-01 UTC $ENDDATESEC2 seconds" +%y%m%d%H%M%SZ`
		openssl ca -batch -name "user" -startdate $STARTDATEZ -enddate $ENDDATEZ -in $1/user/$2.req -out $1/user/$2.pem -config $1/openssl.cnf
		sleep 1
		openssl ca -config $1/openssl.cnf -updatedb
		;;
	  revoked)
		openssl ca -batch -name "user" -startdate $STARTDATEZ -enddate $ENDDATEZ -in $1/user/$2.req -out $1/user/$2.pem -config $1/openssl.cnf
		openssl ca -config $1/openssl.cnf -revoke $1/user/$2.pem
		;;
	esac
}

gen_users () {
	mkdir -p $1/user
	gen_user_cert $1 user1 valid
	gen_user_cert $1 user2 expired
	gen_user_cert $1 user3 revoked
}

gen_CRL () {
	mkdir -p $1/crl
	DATE=`date -u +%y%m%d%H%M%S`
	openssl ca -gencrl -config $1/openssl.cnf -out $1/crl/crl-$DATE.pem
	ln -sf crl-$DATE.pem $1/crl/crl.pem
}

gen_ocsp_responder () {
	mkdir -p $1/ocsp
	SUBJECT=`openssl x509 -noout -subject -in $1/ca/cacert.pem`
        SUBJECT=${SUBJECT#*=}
	SUBJECT="${SUBJECT%%CN*}CN=ocsp.$1/emailAddress=ocsp@$1"
        SUBJECT="${SUBJECT// = /=}"
        SUBJECT="/${SUBJECT//, //}"
	#echo "${SUBJECT}"
	openssl genrsa -out $1/ocsp/ocsp.key 2048
	openssl req -batch -new -subj "$SUBJECT" -key $1/ocsp/ocsp.key -out $1/ocsp/ocsp.req -config $1/openssl.cnf
	openssl ca -batch -name "ocsp_responder" -in $1/ocsp/ocsp.req -out $1/ocsp/ocsp.pem -config $1/openssl.cnf

}

create_openssl_conf_orig () {
	cat > openssl.cnf.orig << EOF
######################################################
# OpenSSL config Template
# last modification: 2015-05-10
######################################################
#
# +CA
#  |
#  +-- user certificates
#  +-- server certificates
#  +-- ocsp_responder certificates
#
######################################################

SSL				= CAPWD
RANDFILE			= \$SSL/DOM/ca/private/.rand
default_md                      = sha512

######################################################
[ ca ]
default_ca 			= user

######################################################
[ user ]

dir				= \$SSL/DOM/ca
certs				= \$dir/certs
crl_dir				= \$dir/crl
database			= \$dir/index.txt
new_certs_dir 			= \$dir/newcerts

certificate 			= \$dir/cacert.pem
serial 				= \$dir/serial
crl 				= \$dir/crl.pem
private_key 			= \$dir/private/cakey.pem

x509_extensions			= user_ext

default_days			= 365
default_crl_days		= 7
default_md			= sha512
preserve			= no

policy				= policy_match

######################################################
[ server ]

dir				= \$SSL/DOM/ca
certs				= \$dir/certs
crl_dir				= \$dir/crl
database			= \$dir/index.txt
new_certs_dir 			= \$dir/newcerts

certificate 			= \$dir/cacert.pem
serial 				= \$dir/serial
crl 				= \$dir/crl.pem
private_key 			= \$dir/private/cakey.pem

x509_extensions			= server_ext

default_days			= 365
default_crl_days		= 7
default_md			= sha512
preserve			= no

policy				= policy_match

######################################################
[ ocsp_responder ]

dir				= \$SSL/DOM/ca
certs				= \$dir/certs
crl_dir				= \$dir/crl
database			= \$dir/index.txt
new_certs_dir 			= \$dir/newcerts

certificate 			= \$dir/cacert.pem
serial 				= \$dir/serial
crl 				= \$dir/crl.pem
private_key 			= \$dir/private/cakey.pem

x509_extensions			= ocsp_responder_ext

default_days 			= 365
default_crl_days		= 7
default_md			= sha512
preserve			= no

policy 				= policy_match

######################################################
[ symbian ]
dir				= \$SSL/DOM/ca
certs				= \$dir/certs
crl_dir				= \$dir/crl
database			= \$dir/index.txt
new_certs_dir 			= \$dir/newcerts

certificate 			= \$dir/cacert.pem
serial 				= \$dir/serial
crl 				= \$dir/crl.pem
private_key 			= \$dir/private/cakey.pem

x509_extensions                 = sym_ext

default_days			= 365
default_crl_days		= 7
default_md			= sha512
preserve                        = no

policy                          = policy_match

######################################################
[ x509v3_FQDN ]
subjectAltName=DNS:DOM

######################################################
[ policy_match ]
countryName			= match
stateOrProvinceName		= match
organizationName		= match
organizationalUnitName		= optional
commonName			= supplied
emailAddress			= optional

######################################################
[ req ]
default_bits			= 4096
default_keyfile			= privkey.pem
distinguished_name		= req_distinguished_name
attributes			= req_attributes
x509_extensions			= v3_ca

string_mask			= nombstr

######################################################
[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= DE
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Nordrhein-Westfalen

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= ORG

#organizationalUnitName          = Organizational Unit Name (eg, section)
#organizationalUnitName_default  = Ministry of Truth

commonName			= Common Name (eg, YOUR name)
commonName_max			= 64
commonName_default		= ROOT CA Certificate

emailAddress			= Email Address
emailAddress_max		= 40
emailAddress_default		= rootca@DOM

######################################################
[ req_attributes ]
# nothing ;-)

######################################################
[ ocsp_responder_ext ]

# These extensions are added when a ocsp-server certificate is issued
keyUsage			= digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage		= OCSPSigning
subjectKeyIdentifier		= hash
authorityKeyIdentifier		= keyid,issuer:always
subjectAltName			= email:copy
issuerAltName			= issuer:copy
crlDistributionPoints   	= URI:http://crl.DOM
nsCertType			= server
nsComment			= "This is a OCSP test certificate!"

######################################################
[ user_ext ]

# These extensions are added when a user certificate is issued
keyUsage			= digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage		= clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2
subjectKeyIdentifier		= hash
authorityKeyIdentifier		= keyid,issuer:always
subjectAltName			= email:copy
issuerAltName			= issuer:copy
crlDistributionPoints		= URI:http://crl.DOM
nsCertType			= client, email
nsComment			= "This is a USER test certificate!"
authorityInfoAccess		= OCSP;URI:http://ocsp.DOM

######################################################
[ server_ext ]

# These extensions are added when a server certificate is issued
keyUsage			= digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage		= serverAuth
subjectKeyIdentifier		= hash
authorityKeyIdentifier		= keyid,issuer:always
subjectAltName			= email:copy
issuerAltName			= issuer:copy
crlDistributionPoints   	= URI:http://crl.DOM
nsCertType			= server
nsComment			= "This is a SERVER test certificate!"
authorityInfoAccess		= OCSP;URI:http://ocsp.DOM

######################################################
[ sym_ext ]
keyUsage                        = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage                = clientAuth, emailProtection
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always
subjectAltName                  = email:copy
issuerAltName                   = issuer:copy
crlDistributionPoints           = URI:http://crl.DOM
nsCertType                      = client, email, objsign
nsComment                       = "Monkey Laboratory Certificate"
authorityInfoAccess             = OCSP;URI:http://ocsp.DOM
nsCaPolicyUrl                   = http://DOM/ssl/policy.html


######################################################
[ v3_ca ]

# These extensions are added when 'RootCA' _signs_ itself.
basicConstraints		= critical, CA:TRUE
keyUsage			= cRLSign, keyCertSign, keyEncipherment, nonRepudiation, digitalSignature
subjectKeyIdentifier		= hash
authorityKeyIdentifier		= keyid,issuer:always
subjectAltName			= email:copy
issuerAltName			= issuer:copy
crlDistributionPoints		= URI:http://crl.DOM
nsCertType			= sslCA, emailCA, objCA
nsComment			= "This a CA root test certificate!"
authorityInfoAccess		= OCSP;URI:http://ocsp.DOM

######################################################
[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.
issuerAltName			= issuer:copy
authorityKeyIdentifier		= keyid:always,issuer:always

EOF
}

check_variables () {
	# Check DOMAIN and ORG variables
	ERROR=0
	if [ "x$1" = "x" ]; then
		echo "ERROR: Missing domain name!"
		ERROR=1
	fi
	if [ "x$2" = "x" ]; then
		echo "ERROR: Missing organization name!"
		ERROR=1
	fi
	if [ $ERROR = 1 ]; then
		print_usage
		exit
	fi
}

print_usage () {
	echo "$0 <create|delete> name.dom \"org name\""
}

# Check for openssl template configuration

check_openssl_cnf_orig () {
	if [ ! -f openssl.cnf.orig ]; then
		create_openssl_conf_orig
	fi
}

# CA Hierarchy
# 
# ROOT CA Certificate
# O = Organization
# OU = Organization Unit

CMD=$1
DOMAIN=$2
ORG=$3


case $CMD in
    create)
	# Create CA directory
	check_variables $DOMAIN "$ORG"
	check_openssl_cnf_orig

	create_openssl_conf $DOMAIN "$ORG"
	create_CA_folders $DOMAIN
	gen_CA_cert $DOMAIN "$ORG"
	gen_server_cert $DOMAIN www
	gen_server_cert $DOMAIN mail
	gen_users $DOMAIN
	gen_CRL $DOMAIN
	gen_ocsp_responder $DOMAIN
	;;
    delete)
	;;
    *)
	print_usage
	;;
esac

