package com.network;

/*
    Name:- Ganesh Kalyankar
    Roll_No:- 2019058
*/

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.BiFunction;

public class Main {

    public static void main(String[] args) {

        System.out.println("Roll_No :- 2019058");
        System.out.println("Name :- Ganesh Kalyankar");
        System.out.println("############################");

        try (Socket socket = new Socket("localhost", 5000);
             BufferedReader inputFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter outputToServer = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader inputFromUser = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.print("Message: ");
            int Message = Integer.parseInt(inputFromUser.readLine());
            System.out.print("Secret Key: ");
            int secretKey = Integer.parseInt(inputFromUser.readLine());
            System.out.print("Public Key parameters(p,q,e): ");
            String[] pqe = new String[3];
            pqe = inputFromUser.readLine().split(" ");
            int p = Integer.parseInt(pqe[0]);
            int q = Integer.parseInt(pqe[1]);
            int publicExponent = Integer.parseInt(pqe[2]);

            // Compute n = pq (modulus)
            int modulus = p*q;

            // Compute φ(n) = φ(p)φ(q) = (p − 1)(q − 1) = n - (p + q -1), where φ is Euler's totient function.
            int m = (p-1)*(q-1);

            // Determine privateExponent as privateExponent ≡ e−1 (mod φ(n)); i.e., privateExponent is the multiplicative inverse of e (modulo φ(n)).
            int privateExponent=0;
            for (int i=1;i<m;i++){
                if(((publicExponent%m) * (i%m)) %m == 1){
                    privateExponent = i;
                }
            }

//          TAKING SERVER PUBLIC KEY
            String[] server_public_params = inputFromServer.readLine().split(" ");
            int server_publicExponent = Integer.parseInt(server_public_params[0]);
            int server_modulus = Integer.parseInt(server_public_params[1]);

//          OUTPUTS
            System.out.println("-----OUTPUTS-----");

            //Encrypting secret key using server public key.
            String encrypted_secret_key = RSA(BigInteger.valueOf(secretKey),server_publicExponent,server_modulus);
            System.out.println("Encrypted Secret Key: "+encrypted_secret_key);

            //Encrypting message using AES encryption and secret key.
            System.out.println("Encryption Intermediate process:");
            int encrypted_message = AES.encrypt(Message, secretKey);
            System.out.println("Cipher text: "+encrypted_message);

            //Converting original message into digest using MD2 hash algorithm.
            String message_digest = digest(String.valueOf(Message));
            System.out.println("Digest: "+message_digest);

            //Digital signature of the message.
            String client_signature = RSA(new BigInteger(message_digest,16),privateExponent,modulus);
            System.out.println("Digital Signature: "+client_signature);

//          SENDING DATA TO THE SERVER.
            outputToServer.println(encrypted_message);
            outputToServer.println(encrypted_secret_key);
            outputToServer.println(client_signature);
            outputToServer.println(publicExponent+" "+modulus);

        } catch (IOException e) {
            System.out.println("Client Error: " + e.getMessage());

        }

    }

    public static String RSA(BigInteger base, int exponent, int modulus){
        try {
            BigInteger temp = base;
            String str = String.valueOf(base);
            if(str.length()>String.valueOf(modulus).length()){
                str = str.substring(0,5);
                int t = Integer.parseInt(str);
                while (t>=modulus){
                    t = t/10;
                }
                temp = BigInteger.valueOf(t);
            }
            return String.valueOf((temp.pow(exponent)).mod(BigInteger.valueOf(modulus)));

        }catch (Exception e){
            System.out.println("Error Occurred: "+e.getMessage());
            return "-1";
        }
    }

    public static String digest(String Message){
        try
        {
            // invoking the static getInstance() method of the MessageDigest class
            // Notice it has MD5 in its parameter.
            MessageDigest msgDst = MessageDigest.getInstance("MD5");

            // the digest() method is invoked to compute the message digest
            // from an input digest() and it returns an array of byte
            byte[] msgArr = msgDst.digest(Message.getBytes());

            // getting signum representation from byte array msgArr
            BigInteger bi = new BigInteger(1, msgArr);

            // Converting into hex value
            String hshtxt = bi.toString(16);

            while (hshtxt.length() < 32)
            {
                hshtxt = "0" + hshtxt;
            }
            return hshtxt;
        }
        catch (NoSuchAlgorithmException abc)
        {
            throw new RuntimeException(abc);
        }
    }

}
