package com.prog4;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.mindrot.jbcrypt.BCrypt;
import javax.crypto.KeyAgreement;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;




class DatabaseConnection {
    private static final String DB_URL = "jdbc:mysql://ysjcs.net:3306/michaeldrury_motogp"; //Uses motogp because I dont have perms to make a new db
    private static final String DB_USER = "michael.drury";
    private static final String DB_PASSWORD = "Q33ME9CJ";
    
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}



class chatGUI {
    private JFrame frame;
    private JTextField usernameField;
    private JTextField IPField;
    private JTextField portField;
    private JPasswordField passwordField;
    public  static JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;
    private JButton leaveButton;
    private JButton connectButton;
    private JButton logOutButton;
    private JPanel loginPanel;
    private JPanel serverPanel;
    private JPanel chatPanel;
    private ObjectOutputStream outputObjectStream;
    private ObjectInputStream inputObjectStream;
    private String username;
    private Socket socket;
    private Coms messageThread;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new chatGUI().initialize());
    }

    private void initialize() {
        frame = new JFrame("Login");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 200);
        frame.setVisible(true);
        createLoginGUI();
    }

    private void createLoginGUI() {
        

        loginPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        loginPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        loginPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        loginPanel.add(usernameField);

        loginPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        loginPanel.add(passwordField);

        JButton loginButton = new JButton("Login");
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                attemptLogin();
            }
        });
        loginPanel.add(loginButton);

        if (serverPanel != null) {
           frame.remove(serverPanel);
           System.out.println("Removed server panel");
        } 
        frame.setTitle("Login");
        frame.add(loginPanel);
        frame.revalidate();
        frame.repaint();
        
    }

    private void attemptLogin() {
        username = usernameField.getText();
        String userpass = new String(passwordField.getPassword());
        
        boolean auth = userDAO.authenticate(username, userpass);
        
        if (auth) {
            frame.getContentPane().remove(loginPanel);
            System.out.println("Logged in");
            createSocketGUI();
        } else {
            JOptionPane.showMessageDialog(frame, "Invalid username or password", "Login Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void createSocketGUI(){
        

        serverPanel= new JPanel(new GridLayout(3, 2, 5, 5));
        serverPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        serverPanel.add(new JLabel("IP:"));
        IPField= new JTextField("localhost");
        serverPanel.add(IPField);

        serverPanel.add(new JLabel("Port:"));
        portField = new JTextField("7777");
        serverPanel.add(portField);
        

        connectButton = new JButton("Connect");
        connectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                getSocket();
            }
        });
        serverPanel.add(connectButton);


        logOutButton = new JButton("Log Out");
        logOutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createLoginGUI();
            }
        });
        serverPanel.add(logOutButton);
        

        if (loginPanel != null) {
           frame.remove(loginPanel);
           System.out.println("Removed login panel");
        } 

        if (chatPanel != null) {
            frame.remove(chatPanel);
            System.out.println("Removed chat panel");
        }
        frame.setTitle("Join Server");
        frame.add(serverPanel);
        frame.revalidate();
        frame.repaint();
       

    }
    private void getSocket(){
        try{
           int port = Integer.parseInt(portField.getText().trim()); 
           System.out.println("Port: " + port);
           if(port > 1024 && port < 49151 && port != 8080){
              String ip = IPField.getText();
              System.out.println("Port: " + ip);
              try {
                  socket = new Socket(ip,port);
                  initializeChat(socket);
              } catch (Exception e) {
                System.out.println("This socket cannot connect");
                JOptionPane.showMessageDialog(frame, "Cannot connect to this socket. Check you have the right inputs and the target server is running.", "Cannot connect", JOptionPane.ERROR_MESSAGE);
              }
           }
           else{
              System.out.println("This is not a valid port");
              JOptionPane.showMessageDialog(frame, "Use ports between 1024 and 49151 excluding 8080.", "Invald port", JOptionPane.ERROR_MESSAGE);
           }
        }
        catch(NumberFormatException e){
            System.out.println("Port is not a number");
            JOptionPane.showMessageDialog(frame, "Port must be a number between 1024 and 49151.", "Invalid port", JOptionPane.ERROR_MESSAGE);
        }
        catch(Exception e){
            e.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    
    private void initializeChat(Socket socket) {
        try {
            inputObjectStream = new ObjectInputStream(socket.getInputStream());
            outputObjectStream = new ObjectOutputStream(socket.getOutputStream());
            outputObjectStream.flush();

            // Create chat GUI
            createChatGUI();

            // Send initial packet
            Packet initPacket = new Packet(username, "User has joined the chat.");
            try {
                byte[] encryptedPacket = AESUtility.encryptObject(initPacket);
                outputObjectStream.writeObject(encryptedPacket);
                outputObjectStream.flush();
            } catch (IOException e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(frame, "IOerror: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
            catch(Exception e){
                e.printStackTrace();
                JOptionPane.showMessageDialog(frame, "Encrpytion Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }

            // Start message thread
            messageThread = new Coms(socket, inputObjectStream, outputObjectStream);
            new Thread(messageThread).start();

        } catch (SocketException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Connection error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        } catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(frame, "IO error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void createChatGUI() {
        chatPanel = new JPanel(new BorderLayout());
        
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        chatArea.setEditable(false);
        chatPanel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        messageField = new JTextField();
        bottomPanel.add(messageField, BorderLayout.CENTER);
        
        sendButton = new JButton("Send");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        //Sends when you press enter
        messageField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        leaveButton = new JButton("Leave");
        leaveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                messageThread.extCloser(); 
                
                createSocketGUI();
            }
        });

        bottomPanel.add(sendButton, BorderLayout.EAST);
        
        chatPanel.add(bottomPanel, BorderLayout.SOUTH);

        bottomPanel.add(leaveButton, BorderLayout.WEST);
        
        frame.setTitle("Chat - " + username);
        frame.remove(serverPanel);
        frame.add(chatPanel);
        frame.revalidate();
        frame.repaint();
        
        
    }

    private void sendMessage() {
        String message = messageField.getText();
        if (!message.trim().isEmpty()) {
            Packet newPacket = new Packet(username, message);
            try {
                byte[] encryptedPacket = AESUtility.encryptObject(newPacket);
                outputObjectStream.writeObject(encryptedPacket);
                outputObjectStream.flush();
                messageField.setText("");
                chatArea.append(username+": "+message+"\n");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(frame, "No connection to the server", "Error", JOptionPane.ERROR_MESSAGE);
            }
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
                boolean isHashed = BCrypt.checkpw(password, storedPassword);
                try{ 
                  if(isHashed){
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
                  chatGUI.chatArea.append(packet.getUsername() + ": " + packet.getMessage()+ "\n");
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
    private static final String TRANSFORMATION = "AES/GCM/PKCS5Padding";
    private static final byte[] KEY = "CryptKey98473817".getBytes(); //Dont hardcode
    

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

class deffieHellman {
    /* This class is not used
    It was supposed to implement Deffie-Hellman key exchange to replace hardcodes keys
    but was not completed. */
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey serverKey;
    private byte[] sharedSecret;

    /*Many methods in this class can experience NoSuchAlgorithmExceptions
     however the algorithms are hardcoded so there is no scenario where an exception occurs
     hence they just throw it.
     */

    public deffieHellman () throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048); // Key size
        KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate(); 
        this.publicKey = keyPair.getPublic();
    }

    //Preps the public key to be sent to the server
    public byte[] encodePublicKey() {
        return publicKey.getEncoded();
    }

    //Receives and handles the public key
    public void setServerKey(byte[] serverKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverKeyBytes);
        this.serverKey = keyFactory.generatePublic(keySpec);
        generateSecretKey(); //Moves straight to generating the secret key no need to call seperatly
    }

    //Creates the secret key
    private void generateSecretKey()throws Exception{
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(serverKey, true);
        this.sharedSecret = keyAgreement.generateSecret();
    }

    //Preps key for AES
    public byte[] getAESKey()throws Exception{
         MessageDigest hashAlgo = MessageDigest.getInstance("SHA-256");
         return hashAlgo.digest(sharedSecret);
    }

}