# Enable signature verification of update payloads on the BMC (installs
# phosphor-image-signing -> /etc/activationdata/<KeyType>/{publickey,hashfunc}).
PACKAGECONFIG:append = " verify_signature"
