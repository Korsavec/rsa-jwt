
"%JAVA_HOME%\bin\keytool"


Создание сертификата для подписания

.\bin\openssl.exe req -config openssl.cnf -new -x509 -keyout private.pem -out certificate.pem -days 365

private.pem
certificate.pem



Создайте хранилище ключей с именем keystore

"%JAVA_HOME%\bin\keytool" –keystore keystore –genkey –alias client -keyalg rsa

keystore



Генерировать запрос на подпись сертификата

"%JAVA_HOME%\bin\keytool" –keystore keystore –certreq –alias client –keyalg rsa –file client.csr

client.csr



Создать подписанный сертификат для связанного CSR

.\bin\openssl.exe x509 -req -CA certificate.pem -CAkey private.pem -in client.csr -out client.cer -days 365 -CAcreateserial

client.cer



Импортировать сертификат CA в хранилище ключей

"%JAVA_HOME%\bin\keytool" -import -keystore keystore -file certificate.pem -alias theCARoot



Импортировать подписанный сертификат для связанного псевдонима в хранилище ключей

"%JAVA_HOME%\bin\keytool" –import –keystore keystore –file client.cer –alias client


https://youtu.be/34cps7vzBeA