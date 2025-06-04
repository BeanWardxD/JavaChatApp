package com.prog4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.net.SocketException;
import java.security.Key;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.mindrot.jbcrypt.BCrypt;



class DatabaseConnection {
    private static final String DB_URL = "jdbc:mysql://ysjcs.net:3306/placeholder_motogp"; //Uses motogp because I dont have perms to make a new db
    private static final String DB_USER = "placeholder";
    private static final String DB_PASSWORD = "placeholder";
    
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}

class Client{

    private static Socket socket;

    public static void main(String[] args){
        
        
        //Initializes variables
        String username;
        String userpass;
        boolean auth;
        

        //Initializes scanner object for inputs
        Scanner scanner = new Scanner(System.in);
        auth = false;
        username ="Null";
        while (auth == false){
             System.out.println("Please enter your username");
             username = scanner.nextLine();
             System.out.println("Please enter your password");
             userpass = scanner.nextLine(); 
             auth = userDAO.authenticate(username, userpass);
        }

        try{
            Setup setup = new Setup(scanner);
            socket = setup.getSocket();
            ObjectInputStream inputObjectStream = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream outputObjectStream = new ObjectOutputStream(socket.getOutputStream());
            outputObjectStream.flush(); 

            Packet initPacket = new Packet(username, "User has joined the chat.");
    
            try {
                    //Encrypt the packet before sending
                   byte[] encryptedPacket = AESUtility.encryptObject(initPacket);
                   outputObjectStream.writeObject(encryptedPacket);
                   outputObjectStream.flush();
            } catch (Exception e) {
                   e.printStackTrace();
            }

            Coms messageThread = new Coms(socket, inputObjectStream, outputObjectStream);
            
            
            new Thread(messageThread).start();

            while(true){
                
                String message = scanner.nextLine(); 
              
                Packet newPacket = new Packet(username, message);
                try {
                   //Encrypt the packet before sending
                   byte[] encryptedPacket = AESUtility.encryptObject(newPacket);
                   outputObjectStream.writeObject(encryptedPacket);
                   outputObjectStream.flush();
                } catch (Exception e) {
                   System.out.println("No conncetion to the server");
                   break;
               }
             }
        }
        catch(SocketException s){
          s.printStackTrace();
        }
        catch(IOException io){
           io.printStackTrace();
        }
        
    }


    
}

class userDAO{

    public static boolean authenticate(String username, String password) {
        String sql = "SELECT password FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
             stmt.setString(1, username);
             ResultSet rs = stmt.executeQuery();
            
             if (rs.next()) {
                String storedPassword = rs.getString("password");
                try{ 
                  if(BCrypt.checkpw(password, storedPassword)){
                    
                    String checkBan = "SELECT isBanned,unban_timestamp FROM users WHERE username = ?";
                    PreparedStatement banStmt = conn.prepareStatement(checkBan);
                    banStmt.setString(1, username);
                    ResultSet banRS = banStmt.executeQuery();
                    if(banRS.next()){
                        boolean isBanned = banRS.getBoolean("isBanned");
                        if (isBanned){
                          
                            Timestamp unban = banRS.getTimestamp("unban_timestamp");
                            Timestamp now = new Timestamp(System.currentTimeMillis());
                            try{
                              if (unban.before(now)){
                                 String unBan = "UPDATE users SET isBanned = 0, unban_timestamp = NULL WHERE username = ?";
                                 PreparedStatement unbanStmt = conn.prepareStatement(unBan);
                                 unbanStmt.setString(1, username);
                                 unbanStmt.executeUpdate();
                                 return true;
                              }
                              else{
                                 System.out.println("You are temporarily banned");
                                 return false;
                              }
                            }catch(NullPointerException e){
                                System.out.println("You permanently are banned");
                                return false;
                            }
                        

                        }
                        else{
                            return true;
                        }
                    }
                  }
                }catch(IllegalArgumentException e){
                  System.out.println("You password is not hashed correctly");   
                  return false;               
                }
        
             }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        System.out.println("Username or password incorrect");
        return false;
    }

}

class Setup{
    private final Scanner scanner;
    private final Socket socket;

    public Setup(Scanner scanner){
        this.scanner = scanner;
        this.socket = socketer();      
    }


    private Socket socketer(){
        while (true){
           System.out.println("Port: ");
           int port = Integer.parseInt(scanner.nextLine().trim()); 
           if(port > 1024 && port < 49151 && port != 8080){
              System.out.println("IP: ");
              String ip = scanner.nextLine();
              try {
                  Socket trySocket = new Socket(ip,port);
                  return trySocket;
              } catch (Exception e) {
                System.out.println("This socket cannot connect");
              }
           }
           else{
              System.out.println("This is not a valid port");
           }
        }
    }

    public Socket getSocket(){
        return socket;
    }
}

class Coms implements Runnable{
    Socket socket;
    ObjectInputStream input;
    ObjectOutputStream output;

    public Coms(Socket socket,ObjectInputStream input,ObjectOutputStream output){
        this.socket = socket;
        this.input = input;
        this.output = output;

    }

    private void closer(Socket socket, ObjectInputStream packetInput, ObjectOutputStream packetOutput){
         try{
             if(packetOutput != null){
                 packetOutput.close();
             }
             if(packetInput != null){
                 packetInput.close();
             }
             if(socket != null){
                 socket.close();
             }
         }
         catch(IOException e){
             e.printStackTrace();
         }

    }

    public void extCloser(){
        closer(socket, input, output);
    }

    @Override
    public void run(){
        try {
          while(socket.isConnected()){
             Object receivedPacket = input.readObject();
              if (receivedPacket instanceof byte[]) {
                  Packet packet = (Packet) AESUtility.decryptObject ((byte[])receivedPacket);
                  System.out.println(packet.getUsername() + ": " + packet.getMessage()); 
              }
          }
                        
        }
        catch (Exception e) {
          closer(socket,input,output);
        }

    }
}


class Packet implements Serializable{

    private final String message;
    private final String username;
    private final String time;
    private final Date date;

    //Constructor 
    public Packet(String username, String message){
        this.date = new Date(); 
        this.time = String.format("%tT", date); 
        this.username = username;
        this.message = message;
      }

    //Getters (No setters to prevent changes before the object is sent)
    public Date getDate() {
        return date;
    }

    public String getTime() {
        return time;
    }

    public String getUsername() {
        return username;
    }

    public String getMessage() {
        return message;
    }
}

class AESUtility {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final byte[] KEY = "CryptKey98473817".getBytes(); 
    

    public static byte[] encryptObject(Serializable object) throws Exception {
        //Serialize the object
        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
        objectOutput.writeObject(object);
        objectOutput.flush();
        byte[] serialized = byteOutput.toByteArray();
        
        //Encrypt
        Key key = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(serialized);
    }
    
    public static Object decryptObject(byte[] encryptedBytes) throws Exception {
        //Decrypt
        Key key = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] serialized = cipher.doFinal(encryptedBytes);
        
        //Deserialize
        ByteArrayInputStream byteInput = new ByteArrayInputStream(serialized);
        ObjectInputStream objectInput = new ObjectInputStream(byteInput);
        return objectInput.readObject();
    }

   

}