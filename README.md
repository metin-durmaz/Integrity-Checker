# Integrity-Checker
basic directory integrity checking program with using hash functions and digital signatures.

# How To Run
javac *.java

java ichecker createCert -k "/PATH/(privateKeyFileName).key" -c "/PATH/(certificateFileName).cer"

java ichecker createReg -r "/PATH/(registiryFileName).txt" -p "/PATH/monitoredDirectory" -l "/PATH/(logFileName).txt" -h hashType -k "/PATH/(privateKeyFileName).key"

java ichecker check -r "/PATH/(registiryFileName).txt" -p "/PATH/monitoredDirectory" -l "/PATH/(logFileName).txt" -h hashType -c "/PATH/(certificateFileName).cer"
