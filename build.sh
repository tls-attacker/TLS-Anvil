mkdir build-dependencies
cd build-dependencies/
git clone https://github.com/tls-attacker/ModifiableVariable.git

git clone https://github.com/tls-attacker/ASN.1-Tool.git

git clone https://github.com/tls-attacker/X509-Attacker.git

git clone https://github.com/tls-attacker/TLS-Attacker.git
git clone https://github.com/tls-attacker/TLS-Scanner.git
( cd TLS-Scanner && git submodule update --init --recursive )

cd ..

docker build -f Dockerfile . -t tlsanvil
