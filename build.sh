mkdir build-dependencies
cd build-dependencies/
git clone https://github.com/tls-attacker/ModifiableVariable.git
( cd ModifiableVariable && git checkout e1f537e6874e352c9284c5a6516b81118f26b754 )

git clone https://github.com/tls-attacker/ASN.1-Tool.git
( cd ASN.1-Tool && git checkout 05370b36d6f0dcc0187472b1557eeba410ca3563 ) 

git clone https://github.com/tls-attacker/X509-Attacker.git
( cd X509-Attacker && git checkout 77ce56af7b8fa951224bb1f47b5e637e365b7968 )

git clone https://github.com/tls-attacker/TLS-Attacker.git
( cd TLS-Attacker && git checkout 0e94899fcf2673e540fb1dec37a3fbb2b3520381 )

git clone https://github.com/tls-attacker/TLS-Scanner.git
( cd TLS-Scanner && git checkout f0780ea22664939ea42a31719cf30a3b9ce1bb7c && git submodule update --init --recursive )

cd ..

docker build -f Dockerfile . -t tlsanvil
