#!/bin/bash

create_openssl_conf () {
	cp openssl.cnf.orig openssl.cnf
	CAPWD=$(echo $PWD | sed 's/\//\\\//g')
	sed "s/CAPWD/$CAPWD/" -i openssl.cnf
	sed "s/DOM/$1/g" -i openssl.cnf
	sed "s/ORG/$2/g" -i openssl.cnf
}

create_CA_folders () {
	if [ -d $1 ]; then
		rm -r $1
	fi
	mkdir $1
	mkdir $1/private
	chmod 700 $1/private
	mkdir $1/certs
	mkdir $1/newcerts
	echo "01" > $1/serial
	touch $1/index.txt

}

# create CA Root Certificate Private Key
gen_CA_cert () {
	openssl genrsa -out $1/private/cakey.pem 2048
	openssl req -batch -new -x509 -days 3650 -key $1/private/cakey.pem -out $1/cacert.pem -config openssl.cnf
}

gen_server_cert () {
	if [ -d server ]; then
		rm -r server
	fi
	mkdir server
	SUBJECT=`openssl x509 -noout -subject -in $1/cacert.pem`
	SUBJECT=${SUBJECT#* }
	SUBJECT="${SUBJECT%%CN*}CN=www.$1/emailAddress=webmaster@$1"
	#echo "${SUBJECT}"
	openssl genrsa -out server/www.key 2048
	openssl req -batch -new -subj "$SUBJECT" -key server/www.key -out server/www.req -config openssl.cnf
	openssl ca -batch -name "server" -in server/www.req -out server/www.pem -config openssl.cnf

}

gen_user_cert () {
	SUBJECT=`openssl x509 -noout -subject -in $1/cacert.pem`
	SUBJECT=${SUBJECT#* }
	SUBJECT="${SUBJECT%%CN*}CN=$2/emailAddress=$2@$1"
	STARTDATE=`openssl x509 -noout -startdate -in $1/cacert.pem`
	STARTDATE=${STARTDATE#*=}
	STARTDATEZ=`date -u -d "$STARTDATE" +%y%m%d%H%M%SZ`
	ENDDATESEC=`date -u -d "$STARTDATE" +%s`
	ENDDATESEC2=$(($ENDDATESEC+31536000))
	ENDDATEZ=`date -u -d "1970-01-01 UTC $ENDDATESEC2 seconds" +%y%m%d%H%M%SZ`
	openssl genrsa -out user/$2.key 2048
	openssl req -batch -new -subj "$SUBJECT" -key user/$2.key -out user/$2.req -config openssl.cnf
	case $3 in
	  valid)
		STARTDATE=`date -u -d "$STARTDATE" +%y%m%d%H%M%SZ`
		openssl ca -batch -name "user" -startdate $STARTDATEZ -enddate $ENDDATEZ -in user/$2.req -out user/$2.pem -config openssl.cnf
		;;
	  expired)
		ENDDATESEC2=$(($ENDDATESEC+1))
		ENDDATEZ=`date -u -d "1970-01-01 UTC $ENDDATESEC2 seconds" +%y%m%d%H%M%SZ`
		openssl ca -batch -name "user" -startdate $STARTDATEZ -enddate $ENDDATEZ -in user/$2.req -out user/$2.pem -config openssl.cnf
		sleep 1
		openssl ca -config openssl.cnf -updatedb
		;;
	  revoked)
		openssl ca -batch -name "user" -startdate $STARTDATEZ -enddate $ENDDATEZ -in user/$2.req -out user/$2.pem -config openssl.cnf
		openssl ca -config openssl.cnf -revoke user/$2.pem
		;;
	esac
}

gen_users () {
	if [ -d user ]; then
		rm -r user
	fi
	mkdir user
	gen_user_cert $1 user1 valid
	gen_user_cert $1 user2 expired
	gen_user_cert $1 user3 revoked
}

gen_CRL () {
	if [ -d crl ]; then
		rm -r crl
	fi
	mkdir crl
	DATE=`date -u +%y%m%d%H%M%S`
	openssl ca -gencrl -config openssl.cnf -out crl/crl-$DATE.pem
	ln -sf crl-$DATE.pem crl/crl.pem
}

gen_ocsp_responder () {
	if [ -d ocsp ]; then
		rm -r ocsp
	fi
	mkdir ocsp
	SUBJECT=`openssl x509 -noout -subject -in $1/cacert.pem`
	SUBJECT=${SUBJECT#* }
	SUBJECT="${SUBJECT%%CN*}CN=ocsp.$1/emailAddress=ocsp@$1"
	#echo "${SUBJECT}"
	openssl genrsa -out ocsp/ocsp.key 2048
	openssl req -batch -new -subj "$SUBJECT" -key ocsp/ocsp.key -out ocsp/ocsp.req -config openssl.cnf
	openssl ca -batch -name "ocsp_responder" -in ocsp/ocsp.req -out ocsp/ocsp.pem -config openssl.cnf

}

create_openssl_conf_orig () {
	cat << EOF | uudecode
begin-base64 644 openssl.cnf.orig
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjCiMgT3BlblNTTCBjb25maWcgVGVtcGxhdGUKIyBsYXN0IG1v
ZGlmaWNhdGlvbjogMjAxMy0wOC0xNQojIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKIwojICtDQQojICB8
CiMgICstLSB1c2VyIGNlcnRpZmljYXRlcwojICArLS0gc2VydmVyIGNlcnRp
ZmljYXRlcwojICArLS0gb2NzcF9yZXNwb25kZXIgY2VydGlmaWNhdGVzCiMK
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjCgpTU0wJCQkJPSBDQVBXRApSQU5ERklMRQkJCT0gJFNTTC9E
T00vcHJpdmF0ZS8ucmFuZAoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjClsgY2EgXQpkZWZhdWx0X2Nh
IAkJCT0gdXNlcgoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjClsgdXNlciBdCgpkaXIJCQkJPSAkU1NM
L0RPTQpjZXJ0cwkJCQk9ICRkaXIvY2VydHMKY3JsX2RpcgkJCQk9ICRkaXIv
Y3JsCmRhdGFiYXNlCQkJPSAkZGlyL2luZGV4LnR4dApuZXdfY2VydHNfZGly
IAkJCT0gJGRpci9uZXdjZXJ0cwoKY2VydGlmaWNhdGUgCQkJPSAkZGlyL2Nh
Y2VydC5wZW0Kc2VyaWFsIAkJCQk9ICRkaXIvc2VyaWFsCmNybCAJCQkJPSAk
ZGlyL2NybC5wZW0KcHJpdmF0ZV9rZXkgCQkJPSAkZGlyL3ByaXZhdGUvY2Fr
ZXkucGVtCgp4NTA5X2V4dGVuc2lvbnMJCQk9IHVzZXJfZXh0CgpkZWZhdWx0
X2RheXMJCQk9IDM2NQpkZWZhdWx0X2NybF9kYXlzCQk9IDcKZGVmYXVsdF9t
ZAkJCT0gc2hhMQpwcmVzZXJ2ZQkJCT0gbm8KCnBvbGljeQkJCQk9IHBvbGlj
eV9tYXRjaAoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjClsgc2VydmVyIF0KCmRpcgkJCQk9ICRTU0wv
RE9NCmNlcnRzCQkJCT0gJGRpci9jZXJ0cwpjcmxfZGlyCQkJCT0gJGRpci9j
cmwKZGF0YWJhc2UJCQk9ICRkaXIvaW5kZXgudHh0Cm5ld19jZXJ0c19kaXIg
CQkJPSAkZGlyL25ld2NlcnRzCgpjZXJ0aWZpY2F0ZSAJCQk9ICRkaXIvY2Fj
ZXJ0LnBlbQpzZXJpYWwgCQkJCT0gJGRpci9zZXJpYWwKY3JsIAkJCQk9ICRk
aXIvY3JsLnBlbQpwcml2YXRlX2tleSAJCQk9ICRkaXIvcHJpdmF0ZS9jYWtl
eS5wZW0KCng1MDlfZXh0ZW5zaW9ucwkJCT0gc2VydmVyX2V4dAoKZGVmYXVs
dF9kYXlzCQkJPSAzNjUKZGVmYXVsdF9jcmxfZGF5cwkJPSA3CmRlZmF1bHRf
bWQJCQk9IHNoYTEKcHJlc2VydmUJCQk9IG5vCgpwb2xpY3kJCQkJPSBwb2xp
Y3lfbWF0Y2gKCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIwpbIG9jc3BfcmVzcG9uZGVyIF0KCmRpcgkJ
CQk9ICRTU0wvRE9NCmNlcnRzCQkJCT0gJGRpci9jZXJ0cwpjcmxfZGlyCQkJ
CT0gJGRpci9jcmwKZGF0YWJhc2UJCQk9ICRkaXIvaW5kZXgudHh0Cm5ld19j
ZXJ0c19kaXIgCQkJPSAkZGlyL25ld2NlcnRzCgpjZXJ0aWZpY2F0ZSAJCQk9
ICRkaXIvY2FjZXJ0LnBlbQpzZXJpYWwgCQkJCT0gJGRpci9zZXJpYWwKY3Js
IAkJCQk9ICRkaXIvY3JsLnBlbQpwcml2YXRlX2tleSAJCQk9ICRkaXIvcHJp
dmF0ZS9jYWtleS5wZW0KCng1MDlfZXh0ZW5zaW9ucwkJCT0gb2NzcF9yZXNw
b25kZXJfZXh0CgpkZWZhdWx0X2RheXMgCQkJPSAzNjUKZGVmYXVsdF9jcmxf
ZGF5cwkJPSA3CmRlZmF1bHRfbWQJCQk9IG1kNQpwcmVzZXJ2ZQkJCT0gbm8K
CnBvbGljeSAJCQkJPSBwb2xpY3lfbWF0Y2gKCiMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpbIHN5bWJp
YW4gXQpkaXIJCQkJPSAkU1NML0RPTQpjZXJ0cwkJCQk9ICRkaXIvY2VydHMK
Y3JsX2RpcgkJCQk9ICRkaXIvY3JsCmRhdGFiYXNlCQkJPSAkZGlyL2luZGV4
LnR4dApuZXdfY2VydHNfZGlyIAkJCT0gJGRpci9uZXdjZXJ0cwoKY2VydGlm
aWNhdGUgCQkJPSAkZGlyL2NhY2VydC5wZW0Kc2VyaWFsIAkJCQk9ICRkaXIv
c2VyaWFsCmNybCAJCQkJPSAkZGlyL2NybC5wZW0KcHJpdmF0ZV9rZXkgCQkJ
PSAkZGlyL3ByaXZhdGUvY2FrZXkucGVtCgp4NTA5X2V4dGVuc2lvbnMgICAg
ICAgICAgICAgICAgID0gc3ltX2V4dAoKZGVmYXVsdF9kYXlzCQkJPSAzNjUK
ZGVmYXVsdF9jcmxfZGF5cwkJPSA3CmRlZmF1bHRfbWQgICAgICAgICAgICAg
ICAgICAgICAgPSBzaGExCnByZXNlcnZlICAgICAgICAgICAgICAgICAgICAg
ICAgPSBubwoKcG9saWN5ICAgICAgICAgICAgICAgICAgICAgICAgICA9IHBv
bGljeV9tYXRjaAoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjClsgeDUwOXYzX0ZRRE4gXQpzdWJqZWN0
QWx0TmFtZT1ETlM6RE9NCgojIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKWyBwb2xpY3lfbWF0Y2ggXQpj
b3VudHJ5TmFtZQkJCT0gbWF0Y2gKc3RhdGVPclByb3ZpbmNlTmFtZQkJPSBt
YXRjaApvcmdhbml6YXRpb25OYW1lCQk9IG1hdGNoCm9yZ2FuaXphdGlvbmFs
VW5pdE5hbWUJCT0gb3B0aW9uYWwKY29tbW9uTmFtZQkJCT0gc3VwcGxpZWQK
ZW1haWxBZGRyZXNzCQkJPSBvcHRpb25hbAoKIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjClsgcmVxIF0K
ZGVmYXVsdF9iaXRzCQkJPSA0MDk2CmRlZmF1bHRfa2V5ZmlsZQkJCT0gcHJp
dmtleS5wZW0KZGlzdGluZ3Vpc2hlZF9uYW1lCQk9IHJlcV9kaXN0aW5ndWlz
aGVkX25hbWUKYXR0cmlidXRlcwkJCT0gcmVxX2F0dHJpYnV0ZXMKeDUwOV9l
eHRlbnNpb25zCQkJPSB2M19jYQoKc3RyaW5nX21hc2sJCQk9IG5vbWJzdHIK
CiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIwpbIHJlcV9kaXN0aW5ndWlzaGVkX25hbWUgXQpjb3VudHJ5
TmFtZQkJCT0gQ291bnRyeSBOYW1lICgyIGxldHRlciBjb2RlKQpjb3VudHJ5
TmFtZV9kZWZhdWx0CQk9IERFCmNvdW50cnlOYW1lX21pbgkJCT0gMgpjb3Vu
dHJ5TmFtZV9tYXgJCQk9IDIKCnN0YXRlT3JQcm92aW5jZU5hbWUgICAgICAg
ICAgICAgPSBTdGF0ZSBvciBQcm92aW5jZSBOYW1lIChmdWxsIG5hbWUpCnN0
YXRlT3JQcm92aW5jZU5hbWVfZGVmYXVsdCAgICAgPSBOb3JkcmhlaW4tV2Vz
dGZhbGVuCgowLm9yZ2FuaXphdGlvbk5hbWUJCT0gT3JnYW5pemF0aW9uIE5h
bWUgKGVnLCBjb21wYW55KQowLm9yZ2FuaXphdGlvbk5hbWVfZGVmYXVsdAk9
IE9SRwoKI29yZ2FuaXphdGlvbmFsVW5pdE5hbWUgICAgICAgICAgPSBPcmdh
bml6YXRpb25hbCBVbml0IE5hbWUgKGVnLCBzZWN0aW9uKQojb3JnYW5pemF0
aW9uYWxVbml0TmFtZV9kZWZhdWx0ICA9IE1pbmlzdHJ5IG9mIFRydXRoCgpj
b21tb25OYW1lCQkJPSBDb21tb24gTmFtZSAoZWcsIFlPVVIgbmFtZSkKY29t
bW9uTmFtZV9tYXgJCQk9IDY0CmNvbW1vbk5hbWVfZGVmYXVsdAkJPSBST09U
IENBIENlcnRpZmljYXRlCgplbWFpbEFkZHJlc3MJCQk9IEVtYWlsIEFkZHJl
c3MKZW1haWxBZGRyZXNzX21heAkJPSA0MAplbWFpbEFkZHJlc3NfZGVmYXVs
dAkJPSByb290Y2FARE9NCgojIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKWyByZXFfYXR0cmlidXRlcyBd
CiMgbm90aGluZyA7LSkKCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpbIG9jc3BfcmVzcG9uZGVyX2V4
dCBdCgojIFRoZXNlIGV4dGVuc2lvbnMgYXJlIGFkZGVkIHdoZW4gYSBvY3Nw
LXNlcnZlciBjZXJ0aWZpY2F0ZSBpcyBpc3N1ZWQKa2V5VXNhZ2UJCQk9IGRp
Z2l0YWxTaWduYXR1cmUsIGtleUVuY2lwaGVybWVudCwga2V5QWdyZWVtZW50
CmV4dGVuZGVkS2V5VXNhZ2UJCT0gT0NTUFNpZ25pbmcKc3ViamVjdEtleUlk
ZW50aWZpZXIJCT0gaGFzaAphdXRob3JpdHlLZXlJZGVudGlmaWVyCQk9IGtl
eWlkLGlzc3VlcjphbHdheXMKc3ViamVjdEFsdE5hbWUJCQk9IGVtYWlsOmNv
cHkKaXNzdWVyQWx0TmFtZQkJCT0gaXNzdWVyOmNvcHkKY3JsRGlzdHJpYnV0
aW9uUG9pbnRzICAgCT0gVVJJOmh0dHA6Ly9jcmwuRE9NCm5zQ2VydFR5cGUJ
CQk9IHNlcnZlcgpuc0NvbW1lbnQJCQk9ICJUaGlzIGlzIGEgT0NTUCB0ZXN0
IGNlcnRpZmljYXRlISIKCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpbIHVzZXJfZXh0IF0KCiMgVGhl
c2UgZXh0ZW5zaW9ucyBhcmUgYWRkZWQgd2hlbiBhIHVzZXIgY2VydGlmaWNh
dGUgaXMgaXNzdWVkCmtleVVzYWdlCQkJPSBkaWdpdGFsU2lnbmF0dXJlLCBu
b25SZXB1ZGlhdGlvbiwga2V5RW5jaXBoZXJtZW50LCBkYXRhRW5jaXBoZXJt
ZW50CmV4dGVuZGVkS2V5VXNhZ2UJCT0gY2xpZW50QXV0aCwgZW1haWxQcm90
ZWN0aW9uLCAxLjMuNi4xLjQuMS4zMTEuMjAuMi4yCnN1YmplY3RLZXlJZGVu
dGlmaWVyCQk9IGhhc2gKYXV0aG9yaXR5S2V5SWRlbnRpZmllcgkJPSBrZXlp
ZCxpc3N1ZXI6YWx3YXlzCnN1YmplY3RBbHROYW1lCQkJPSBlbWFpbDpjb3B5
Cmlzc3VlckFsdE5hbWUJCQk9IGlzc3Vlcjpjb3B5CmNybERpc3RyaWJ1dGlv
blBvaW50cwkJPSBVUkk6aHR0cDovL2NybC5ET00KbnNDZXJ0VHlwZQkJCT0g
Y2xpZW50LCBlbWFpbApuc0NvbW1lbnQJCQk9ICJUaGlzIGlzIGEgVVNFUiB0
ZXN0IGNlcnRpZmljYXRlISIKYXV0aG9yaXR5SW5mb0FjY2VzcwkJPSBPQ1NQ
O1VSSTpodHRwOi8vb2NzcC5ET00KCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpbIHNlcnZlcl9leHQg
XQoKIyBUaGVzZSBleHRlbnNpb25zIGFyZSBhZGRlZCB3aGVuIGEgc2VydmVy
IGNlcnRpZmljYXRlIGlzIGlzc3VlZAprZXlVc2FnZQkJCT0gZGlnaXRhbFNp
Z25hdHVyZSwga2V5RW5jaXBoZXJtZW50LCBrZXlBZ3JlZW1lbnQKZXh0ZW5k
ZWRLZXlVc2FnZQkJPSBzZXJ2ZXJBdXRoCnN1YmplY3RLZXlJZGVudGlmaWVy
CQk9IGhhc2gKYXV0aG9yaXR5S2V5SWRlbnRpZmllcgkJPSBrZXlpZCxpc3N1
ZXI6YWx3YXlzCnN1YmplY3RBbHROYW1lCQkJPSBlbWFpbDpjb3B5Cmlzc3Vl
ckFsdE5hbWUJCQk9IGlzc3Vlcjpjb3B5CmNybERpc3RyaWJ1dGlvblBvaW50
cyAgIAk9IFVSSTpodHRwOi8vY3JsLkRPTQpuc0NlcnRUeXBlCQkJPSBzZXJ2
ZXIKbnNDb21tZW50CQkJPSAiVGhpcyBpcyBhIFNFUlZFUiB0ZXN0IGNlcnRp
ZmljYXRlISIKYXV0aG9yaXR5SW5mb0FjY2VzcwkJPSBPQ1NQO1VSSTpodHRw
Oi8vb2NzcC5ET00KCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpbIHN5bV9leHQgXQprZXlVc2FnZSAg
ICAgICAgICAgICAgICAgICAgICAgID0gZGlnaXRhbFNpZ25hdHVyZSwgbm9u
UmVwdWRpYXRpb24sIGtleUVuY2lwaGVybWVudCwgZGF0YUVuY2lwaGVybWVu
dApleHRlbmRlZEtleVVzYWdlICAgICAgICAgICAgICAgID0gY2xpZW50QXV0
aCwgZW1haWxQcm90ZWN0aW9uCnN1YmplY3RLZXlJZGVudGlmaWVyICAgICAg
ICAgICAgPSBoYXNoCmF1dGhvcml0eUtleUlkZW50aWZpZXIgICAgICAgICAg
PSBrZXlpZCxpc3N1ZXI6YWx3YXlzCnN1YmplY3RBbHROYW1lICAgICAgICAg
ICAgICAgICAgPSBlbWFpbDpjb3B5Cmlzc3VlckFsdE5hbWUgICAgICAgICAg
ICAgICAgICAgPSBpc3N1ZXI6Y29weQpjcmxEaXN0cmlidXRpb25Qb2ludHMg
ICAgICAgICAgID0gVVJJOmh0dHA6Ly9jcmwuRE9NCm5zQ2VydFR5cGUgICAg
ICAgICAgICAgICAgICAgICAgPSBjbGllbnQsIGVtYWlsLCBvYmpzaWduCm5z
Q29tbWVudCAgICAgICAgICAgICAgICAgICAgICAgPSAiTW9ua2V5IExhYm9y
YXRvcnkgQ2VydGlmaWNhdGUiCmF1dGhvcml0eUluZm9BY2Nlc3MgICAgICAg
ICAgICAgPSBPQ1NQO1VSSTpodHRwOi8vb2NzcC5ET00KbnNDYVBvbGljeVVy
bCAgICAgICAgICAgICAgICAgICA9IGh0dHA6Ly9ET00vc3NsL3BvbGljeS5o
dG1sCgoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjClsgdjNfY2EgXQoKIyBUaGVzZSBleHRlbnNpb25z
IGFyZSBhZGRlZCB3aGVuICdSb290Q0EnIF9zaWduc18gaXRzZWxmLgpiYXNp
Y0NvbnN0cmFpbnRzCQk9IGNyaXRpY2FsLCBDQTpUUlVFCmtleVVzYWdlCQkJ
PSBjUkxTaWduLCBrZXlDZXJ0U2lnbiwga2V5RW5jaXBoZXJtZW50LCBub25S
ZXB1ZGlhdGlvbiwgZGlnaXRhbFNpZ25hdHVyZQpzdWJqZWN0S2V5SWRlbnRp
ZmllcgkJPSBoYXNoCmF1dGhvcml0eUtleUlkZW50aWZpZXIJCT0ga2V5aWQs
aXNzdWVyOmFsd2F5cwpzdWJqZWN0QWx0TmFtZQkJCT0gZW1haWw6Y29weQpp
c3N1ZXJBbHROYW1lCQkJPSBpc3N1ZXI6Y29weQpjcmxEaXN0cmlidXRpb25Q
b2ludHMJCT0gVVJJOmh0dHA6Ly9jcmwuRE9NCm5zQ2VydFR5cGUJCQk9IHNz
bENBLCBlbWFpbENBLCBvYmpDQQpuc0NvbW1lbnQJCQk9ICJUaGlzIGEgQ0Eg
cm9vdCB0ZXN0IGNlcnRpZmljYXRlISIKYXV0aG9yaXR5SW5mb0FjY2VzcwkJ
PSBPQ1NQO1VSSTpodHRwOi8vb2NzcC5ET00KCiMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpbIGNybF9l
eHQgXQoKIyBDUkwgZXh0ZW5zaW9ucy4KIyBPbmx5IGlzc3VlckFsdE5hbWUg
YW5kIGF1dGhvcml0eUtleUlkZW50aWZpZXIgbWFrZSBhbnkgc2Vuc2UgaW4g
YSBDUkwuCmlzc3VlckFsdE5hbWUJCQk9IGlzc3Vlcjpjb3B5CmF1dGhvcml0
eUtleUlkZW50aWZpZXIJCT0ga2V5aWQ6YWx3YXlzLGlzc3VlcjphbHdheXMK
Cg==
====
E
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
	echo "$0 name.dom \"org name\""
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

DOMAIN=$1
ORG=$2

check_variables $DOMAIN "$ORG"
check_openssl_cnf_orig

create_openssl_conf $DOMAIN "$ORG"
create_CA_folders $DOMAIN
gen_CA_cert $DOMAIN "$ORG"
gen_server_cert $DOMAIN
gen_users $DOMAIN
gen_CRL
gen_ocsp_responder $DOMAIN


