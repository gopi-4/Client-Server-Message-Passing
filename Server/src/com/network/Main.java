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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) {

        System.out.println("Roll_No :- 2019058");
        System.out.println("Name :- Ganesh Kalyankar");
        System.out.println("############################");

        try(Socket serverSocket = (new ServerSocket(5000)).accept();
            BufferedReader inputFromClient = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
            PrintWriter outputToClient = new PrintWriter(serverSocket.getOutputStream(), true);
            BufferedReader inputFromUser = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("Client Connected");

            System.out.print("Public Key parameters(p,q,e): ");
            String[] pqe;
            pqe = inputFromUser.readLine().split(" ");

            int p = Integer.parseInt(pqe[0]);
            int q = Integer.parseInt(pqe[1]);
            int publicExponent = Integer.parseInt(pqe[2]);

            // Compute n = pq (modulus)
            int modulus = p*q;

            // Compute φ(n) = φ(p)φ(q) = (p − 1)(q − 1) = n - (p + q -1), where φ is Euler's totient function.
            int m = (p-1)*(q-1);

            // Determine privateExponent as privateExponent ≡ e−1 (mod φ(n)); i.e., privateExponent is the multiplicative inverse of e (modulo φ(n)).
            int privateExponent = 0;
            for (int i=1;i<m;i++){
                if(((publicExponent%m) * (i%m)) %m == 1){
                    privateExponent = i;
                }
            }

//          SENDIND SEVER PUBLIC KEY.
            outputToClient.println(publicExponent +" "+ modulus);

//            RECEIVING DATA FROM CLIENT

            //Receving encrypted_message from client
            int encrypted_message = Integer.parseInt(inputFromClient.readLine());

            //Receiving encrypted_secret_key from client
            String encrypted_secret_key = inputFromClient.readLine();

            //Receiving clent_signature
            String client_signature = inputFromClient.readLine();

            //Receiving client public key
            String[] client_public_params = inputFromClient.readLine().split(" ");
            int client_publicExponent = Integer.parseInt(client_public_params[0]);
            int client_modulus = Integer.parseInt(client_public_params[1]);

//          OUTPUT
            System.out.println("-----OUTPUT-----");

            //Decrypting encrypted secret key.
            String secret_key = RSA(BigInteger.valueOf(Integer.parseInt(encrypted_secret_key)),privateExponent,modulus);
            System.out.println("Decrypted Secret key:"+secret_key);

            //Decrypting ciphertext using AES decryption and secret key.
            System.out.println("Decryption Intermediate process:");
            int msg = AES.decrypt(encrypted_message,Integer.parseInt(secret_key));
            System.out.println("Decrypted Plaintext: "+msg);

            //Converting message into digest using MD2 hash algorithm.
            String digest = digest(String.valueOf(msg));
            System.out.println("Message Digest: "+digest);

            //Digital signature of the message.
            String signature = RSA(new BigInteger(digest,16),client_publicExponent,client_modulus);
            System.out.println("Intermediate verification code: "+signature);

            String trunckeddigest = RSA(BigInteger.valueOf(Integer.parseInt(client_signature)),client_publicExponent,client_modulus);

            BigInteger digestValue = new BigInteger(digest,16);
            String str = String.valueOf(digestValue);

            str = str.substring(0,5);
            int t = Integer.parseInt(str);
            while (t>=client_modulus){
                t = t/10;
            }
            String digestlessthanmodulus = String.valueOf(t);
            
            //Validating digital signature.
            if(trunckeddigest.equals(digestlessthanmodulus)){
                System.out.println("Signature verified");
            }else {
                System.out.println("Signature Not Verified");
            }

        } catch(IOException e) {
            System.out.println("Server exception " + e.getMessage());
        }

    }

    public static String RSA(BigInteger base, int exponent, int modulus){
        try {

            return String.valueOf((base.pow(exponent)).mod(BigInteger.valueOf(modulus)));

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
