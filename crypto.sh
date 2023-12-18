#!/bin/bash

#Functions

#Error Handling Fucntio
err () {
	echo "ERROR vaida.r: $*" > /dev/stderr
	rm -rf tmp
	exit 1
}

#Function to Check if the Public Key is malformed
check_mal_pub () {
if [ $1 -ne 0 ];
then
	err "The Public Key is malformed for Receiver $2"
fi
}


#Fucntion to Encrypt the Secret Key with the Public Keys of each receiver
pubkeyenc () {

#Receiver 1 Secret Key Encryption	
touch receiver1_enc_key
openssl rsautl -encrypt -inkey ./tmp/RECEIVER1_PUB -pubin -in ./tmp/SECRET_KEY -out receiver1_enc_key 2> /dev/null
#Checking if the Public key is malformed
check_mal_pub $? 1
echo 'Encrypted the Secret Key for Receiver 1'


#Receiver 2 Secret Key Encryption
touch receiver2_enc_key
openssl rsautl -encrypt -inkey ./tmp/RECEIVER2_PUB -pubin -in ./tmp/SECRET_KEY -out receiver2_enc_key 2> /dev/null
#Checking if the Public key is malformed
check_mal_pub $? 2
echo 'Encrypted the Secret Key for Receiver 2'


#Receiver 3 Secret Key Encryption
touch receiver3_enc_key
openssl rsautl -encrypt -inkey ./tmp/RECEIVER3_PUB -pubin -in ./tmp/SECRET_KEY -out receiver3_enc_key 2> /dev/null
#Checking if the Public key is malformed
check_mal_pub $? 3
echo 'Encrypted the Secret Key for Receiver 3'

}


#Secret Message Encryptor Function
encryptor () {
	#Generating a random secret passphrase for the secret key
        openssl rand -out ./tmp/secret 32
	#Generating the secret key
        openssl enc -aes-256-cbc -pbkdf2 -k ./tmp/secret -P -md sha1 > ./tmp/SECRET_KEY
		
	#echo 'The Secret Key is'
        #cat ./tmp/SECRET_KEY
        
	#Creating temporary files for handling the command line arguments
	touch ./tmp/RECEIVER1_PUB;cat $1 > ./tmp/RECEIVER1_PUB
	touch ./tmp/RECEIVER2_PUB;cat $2 > ./tmp/RECEIVER2_PUB
	touch ./tmp/RECEIVER3_PUB;cat $3 > ./tmp/RECEIVER3_PUB
	touch ./tmp/SENDER_PRIV;cat $4 > ./tmp/SENDER_PRIV
	touch enc.msg
	#Calling the fucntion to encrypt the secret key with the receiver's public key
	PT_FILE=$5
	ET_ZIP=$6
	
	#Checking if the Plain Text File exists
	if [ ! -f $PT_FILE ];
	then
		#VAR=1
		err "Input File for encryption does not exist"
		#exit 1
	fi

	echo 'Encrypting..'
	#Calling the function to encrypt the secret key with the receiver's public key
	pubkeyenc


	#touch $ET_ZIP
	#Encrypting the Message with the randomly generated secret key
	openssl enc -aes-256-cbc -pbkdf2 -in ${PT_FILE} -out enc.msg -pass file:./tmp/SECRET_KEY
        #Deleting the Secret Key
        rm ./tmp/SECRET_KEY

	
	#Signing the hash of the encrypted message
	openssl dgst -sha256 -sign ./tmp/SENDER_PRIV -out sign.sha256 enc.msg 2> /dev/null
	if [ $? -ne 0 ];
	then
		err "The Sender's Private key is malformed"
	fi

	echo 'The Encrypted Message has been hashed and signed'



	#Zipping the files created
	zip -m ${ET_ZIP} receiver1_enc_key receiver2_enc_key receiver3_enc_key sign.sha256 enc.msg > /dev/null
	 if [ $? -eq 0 ];
	 then
		 echo "The Files have been zipped and saved into ${ET_ZIP}"
	 fi

}



#Decryptor Fucntion
decryptor () {
	#echo 'Decrypting..'
	touch ./tmp/RECEIVER_PRIV; cat $1 > ./tmp/RECEIVER_PRIV
	touch ./tmp/SENDER_PUB; cat $2 > ./tmp/SENDER_PUB
	ETD_ZIP=$3
	DT_FILE=$4

	#Checking if the Encrypted  File exists
	if [ ! -f $ETD_ZIP ];
	then
		err "Input File not does not exist"
		exit 1
	fi

	echo 'Encrypting..'






	echo "Unzipping the contents of ${ETD_ZIP}"
	unzip -d ./dec/ ${ETD_ZIP} > /dev/null
	
	
	


	#rm $ETD_ZIP
	echo 'Decrypting..'

	
#Verifying the hash of the Digital Signature
        VAR=`openssl dgst -sha256 -verify ./tmp/SENDER_PUB -signature ./dec/sign.sha256 ./dec/enc.msg 2>&1`

	if [ $? -eq 0 ];
	then
		echo 'The Digital Signature of the Sender has been Verified'
	else
		#echo 'ERROR vaida.r: The Signature of the Sender could not be Verified'
		err "The Signature of the Sender could not be verified"
		
	fi


	#Decrypting the encrypted secret key with the public key of the receiver
        #r1='receiver1.priv'
	if [[ "$1" == *"receiver1.priv"* ]];
	then
		#echo 'Receiver1'
		openssl rsautl -decrypt -inkey ./tmp/RECEIVER_PRIV -in ./dec/receiver1_enc_key -out ./tmp/dec_secret_key
	elif [[ "$1" = *"receiver2.priv"* ]];
	then
		#echo 'Receiver2'
		openssl rsautl -decrypt -inkey ./tmp/RECEIVER_PRIV -in ./dec/receiver2_enc_key -out ./tmp/dec_secret_key
	elif [[ "$1" = *"receiver3.priv"* ]];
	then
		#echo 'Receiver3'
		openssl rsautl -decrypt -inkey ./tmp/RECEIVER_PRIV -in ./dec/receiver3_enc_key -out ./tmp/dec_secret_key
	else
		echo 'Please Enter the Correct Receiver'
	fi
      # rm receiver1_enc_key receiver2_enc_key receiver3_enc_key



	#Decrypting the Encrypted file
       #echo 'Decrypting'	
openssl enc -aes-256-cbc -d -pbkdf2 -in ./dec/enc.msg -out $DT_FILE -pass file:./tmp/dec_secret_key

	
	echo "The Decrypted Message is: `cat $DT_FILE`"  
	rm -rf dec
	#cat $DT_FILE
	#rm $ETD_FILE $DT_FILE sign.sha256

}




#Variable to decide encryption or decryption
CRYPT=$1

#Creating a temporary directory to manage files
mkdir tmp

#AES Encryption algorithm - Encrypting the message


if [ $CRYPT = '-e' ];
then 
	if [ $# -eq 7 ];
	then
		encryptor $2 $3 $4 $5 $6 $7
	#elif [ $# < 7 ];
	#then
		#err "Please enter all the required arguments"
	else
		err "Please enter 7 arguments"
		
	fi
	rm -rf tmp


elif [ $CRYPT = '-d' ];
then
	if [ $# -eq 5 ];
	then
		decryptor $2 $3 $4 $5
	else
		err "Please enter all the required arguments"
		
	fi
	rm -rf tmp
else
	err "Please enter the correct option"
	rm -rf tmp
fi

#rm -rf tmp

