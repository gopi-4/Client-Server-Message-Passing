package com.network;

/*
    Name:- Ganesh Kalyankar
    Roll_No:- 2019058
*/

public class AES {

//    Function to multiply integer and a nibble.
    public static int multiply(int n1, int n2){
        int num=0;
        while( n2>0 ){
            if ((n2 & 0b1)>0)
                num ^= n1;
            n1 <<= 1;
            if ((n1 & 0b10000)>0)
                n1 ^= 0b11;
            n2 >>= 1;
        }
        return (num & 0b1111);
    }

//    Function to mix the columns for encryption.
    public static String mixColumnsEncrypt(String s){
        int nibble1=Integer.parseInt(s.substring(0,4),2);
        int nibble2=Integer.parseInt(s.substring(4,8),2);
        int nibble3=Integer.parseInt(s.substring(8,12),2);
        int nibble4=Integer.parseInt(s.substring(12),2);
        int part1=nibble1^multiply(4,nibble2);
        int part2=nibble2^multiply(4,nibble1);
        int part3=nibble3^multiply(4,nibble4);
        int part4=nibble4^multiply(4,nibble3);
        return dec2bin(part1,4)+dec2bin(part2,4)+dec2bin(part3,4)+dec2bin(part4,4);
    }

//    Function to mix the columns for encryption.
    public static String mixColumnsDecrypt(String s){
        int nibble1=Integer.parseInt(s.substring(0,4),2);
        int nibble2=Integer.parseInt(s.substring(4,8),2);
        int nibble3=Integer.parseInt(s.substring(8,12),2);
        int nibble4=Integer.parseInt(s.substring(12),2);
        int part1=multiply(9,nibble1)^multiply(2,nibble2);
        int part2=multiply(2,nibble1)^multiply(9,nibble2);
        int part3=multiply(9,nibble3)^multiply(2,nibble4);
        int part4=multiply(2,nibble3)^multiply(9,nibble4);

        return dec2bin(part1,4)+dec2bin(part2,4)+dec2bin(part3,4)+dec2bin(part4,4);

    }

//    Function to convert a decimal into n bits binary number.
    public static String dec2bin(int n, int bits){
        String str = Integer.toBinaryString(n);
        int t = bits-str.length();
        while (t>0){
            str = "0"+str;
            t--;
        }
        return str;
    }

//    Function for nibble substitution while encryption.
    public static String EncryptionNibbleSubstitute(String b){
        String[] str = {"1001","0100","1010","1011","1101","0001","1000","0101","0110","0010","0000","0011","1100","1110","1111","0111"};
        return str[Integer.parseInt(b,2)];
    }

//    Function for nibble substitution while decryption.
    public static String DecryptionNibbleSubstitute(String b){
        String[] str = {"1010","0101","1001","1011","0001","0111","1000","1111","0110","0000","0010","0011","1100","0100","1101","1110"};
        return str[Integer.parseInt(b,2)];
    }

//    Function to XOR two binary strings.
    public static String  xoring(String a, String b){

        String ans = "";
        // Loop to iterate over the
        // Binary Strings
        for (int i = 0; i < a.length(); i++)
        {
            // If the Character matches
            if (a.charAt(i) == b.charAt(i))
                ans += "0";
            else
                ans += "1";
        }
        return ans;
    }

//    Function to generate sub-keys from a secret key.
    public static String[] subKeys(String secret_key){
        String[] result = new String[3];
        result[0] = secret_key;

        String w2 = String.valueOf(xoring(xoring(secret_key.substring(0,8),"10000000"),EncryptionNibbleSubstitute(secret_key.substring(12,16))+EncryptionNibbleSubstitute(secret_key.substring(8,12))));
        String w3 = String.valueOf(xoring(w2,secret_key.substring(8,16)));
        result[1] = w2+w3;

        String w4 = String.valueOf(xoring(xoring(w2,"00110000"),EncryptionNibbleSubstitute(w3.substring(4,8))+EncryptionNibbleSubstitute(w3.substring(0,4))));
        String w5 = String.valueOf(xoring(w4,w3));
        result[2] = w4+w5;

        return result;
    }

//    Fuction to shift the rows(i.e nibble2 <-> nibble4).
    public static String rowShift(String string){
        return string.substring(0,4) + string.substring(12,16) + string.substring(8,12) + string.substring(4,8);
    }

//    Function fo aes encryption of message from secret key.
    public static int encrypt(int message, int key){

//        Converting message and key into binary strings.
        String msg = dec2bin(message,16);
        String secret_key = dec2bin(key,16);

//        Sub-keys of a secret key.
        String[] subKeys = subKeys(secret_key);

//        Round1.
        //Adding subKey0.
        String round0 = String.valueOf(xoring(msg,subKeys[0]));
        System.out.println("\t After Pre-round transformation: "+round0);
        System.out.println("\t Round key K0: "+subKeys[0]);

//        Round2.
        //Substituting nibbles.
        String substitution = EncryptionNibbleSubstitute(round0.substring(0,4)) + EncryptionNibbleSubstitute(round0.substring(4,8)) + EncryptionNibbleSubstitute(round0.substring(8,12)) + EncryptionNibbleSubstitute(round0.substring(12,16));
        System.out.println("\t After Round 1 Substitute nibbles: "+substitution);
        //shift row.
        String rowShift = rowShift(substitution);
        System.out.println("\t After Round 1 Shift rows: "+rowShift);
        //Column mix.
        String columnMix = mixColumnsEncrypt(rowShift);
        System.out.println("\t After Round 1 Mix columns: "+columnMix);
        //Adding subKey1.
        String round1 = String.valueOf(xoring(columnMix,subKeys[1]));
        System.out.println("\t After Round 1 Add round key: "+round1);
        System.out.println("\t Round key K1: "+subKeys[1]);

//        Round3.
        //Substituting nibbles.
        substitution = EncryptionNibbleSubstitute(round1.substring(0,4)) + EncryptionNibbleSubstitute(round1.substring(4,8)) + EncryptionNibbleSubstitute(round1.substring(8,12)) + EncryptionNibbleSubstitute(round1.substring(12,16));
        System.out.println("\t After Round 2 Substitute nibbles: "+substitution);
        //shift row.
        rowShift = rowShift(substitution);
        System.out.println("\t After Round 2 Shift rows:"+rowShift);
        //Adding subKey2.
        String round2 = String.valueOf(xoring(subKeys[2],rowShift));
        System.out.println("\t After Round 2 Add round key: "+round2);
        System.out.println("\t Round Key K2: "+subKeys[2]);

        return Integer.parseInt(round2,2);
    }

//    Function fo aes encryption of message from secret key.
    public static int decrypt(int encrypted_msg, int key){

//        Converting message and key into binary strings.
        String encrypted_msg_binary = dec2bin(encrypted_msg,16);
        String key_binary = dec2bin(key,16);

//        Sub-keys of a secret key.
        String[] subKeys = subKeys(key_binary);

//        Round0.
        //Adding subKey2.
        String firstXOR = xoring(subKeys[2],encrypted_msg_binary);
        System.out.println("\t After Pre-round transformation: "+firstXOR);
        System.out.println("\t Round key K2: "+subKeys[2]);

//        Round1.
        //shift row.
        String firstRowShift = rowShift(firstXOR);
        System.out.println("\t After Round 1 InvShift rows: "+firstRowShift);
        //Substituting nibbles.
        String firstInverseNibbleSubstitute = DecryptionNibbleSubstitute(firstRowShift.substring(0,4))+DecryptionNibbleSubstitute(firstRowShift.substring(4,8))+DecryptionNibbleSubstitute(firstRowShift.substring(8,12))+DecryptionNibbleSubstitute(firstRowShift.substring(12,16));
        System.out.println("\t After Round 1 InvSubstitute nibbles: "+firstInverseNibbleSubstitute);
        //Adding subKey1.
        String secondXOR = xoring(subKeys[1],firstInverseNibbleSubstitute);
        System.out.println("\t After Round 1 InvAdd round key: "+secondXOR);
        System.out.println("\t Round key K1: "+subKeys[1]);

//        Round2.
        //Column mix.
        String mixColumn = mixColumnsDecrypt(secondXOR);
        System.out.println("\t After Round 1 InvMix columns: "+mixColumn);
        //shift row.
        String secondShiftRow = rowShift(mixColumn);
        System.out.println("\t After Round 2 InvShift rows: "+secondShiftRow);
        //Substituting nibbles.
        String secondInverseNibbleSubstitute = DecryptionNibbleSubstitute(secondShiftRow.substring(0,4))+DecryptionNibbleSubstitute(secondShiftRow.substring(4,8))+DecryptionNibbleSubstitute(secondShiftRow.substring(8,12))+DecryptionNibbleSubstitute(secondShiftRow.substring(12,16));
        System.out.println("\t After Round 2 InvSubstitute nibbles: "+secondInverseNibbleSubstitute);
        //Adding subKey0.
        String thirdXOR = xoring(subKeys[0],secondInverseNibbleSubstitute);
        System.out.println("\t After Round 2 Add round key: "+thirdXOR);
        System.out.println("\t Round Key K0: "+subKeys[0]);

        return Integer.parseInt(thirdXOR,2);
    }

}
