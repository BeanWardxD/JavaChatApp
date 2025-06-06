package com.prog4;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import com.sun.management.OperatingSystemMXBean;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

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

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.CardLayout;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import org.mindrot.jbcrypt.BCrypt;


class chatGUI {
    private JFrame frame;
    private JTextField usernameField;
    private JTextField webPort;
    private JTextField chatPort;
    private JPasswordField passwordField;
    public  static JTextArea chatArea;
    private JPanel loginPanel;
    private JPanel mainPanel;
    private CardLayout cardLayout;
    private String username;


    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new chatGUI().initialize());
    }

    private void initialize() {
        frame = new JFrame("Login");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 200);
        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);
        frame.add(mainPanel);
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
        loginButton.addActionListener(e -> attemptLogin());
          
        loginPanel.add(loginButton);

        frame.setTitle("Login");
        mainPanel.add(loginPanel, "login");
        cardLayout.show(mainPanel, "login");
        frame.revalidate();
        frame.repaint();
        
    }

    private void attemptLogin() {
        username = usernameField.getText();
        String userpass = new String(passwordField.getPassword());
        userDAO DAO = new userDAO();
        
        boolean auth = DAO.authenticate(username, userpass);
        
        if (auth) {
            frame.getContentPane().remove(loginPanel);
            System.out.println("Logged in");
            createSocketGUI();
        } else {
            JOptionPane.showMessageDialog(frame, "Invalid username or password (Must be admin)", "Login Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void createSocketGUI(){
        
        
        JPanel serverPanel= new JPanel(new GridLayout(3, 2, 5, 5));
        serverPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        serverPanel.add(new JLabel("Web Server Port:"));
        webPort= new JTextField("8080");
        serverPanel.add(webPort);

        serverPanel.add(new JLabel("Chat Server Port:"));
        chatPort = new JTextField("7777");
        serverPanel.add(chatPort);
        
        Server server = new Server(webPort.getText().trim(), chatPort.getText().trim());

        JButton connectButton = new JButton("Connect");
        connectButton.addActionListener(e -> server.startUp());
           
        serverPanel.add(connectButton);


        JButton logOutButton = new JButton("Log Out");
        logOutButton.addActionListener(e -> createLoginGUI());
        serverPanel.add(logOutButton);
        
        frame.setTitle("Join Server");
        mainPanel.add(serverPanel, "server");
        cardLayout.show(mainPanel, "server");

       

    }

}

class DatabaseConnection {
    private static final String DB_URL = "jdbc:mysql://ysjcs.net:3306/michaeldrury_motogp"; //Uses motogp because I dont have perms to make a new db
    private static final String DB_USER = "michael.drury";
    private static final String DB_PASSWORD = "Q33ME9CJ";
    
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}

class userDAO{

    public boolean authenticate(String username, String password) {
        
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
                                 return isAdmin(username); 
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
                            return isAdmin(username); 
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

    private boolean isAdmin(String username){
        String sql = "SELECT isAdmin FROM users WHERE username = ?";
        username = username;
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
             stmt.setString(1, username);
             ResultSet rs = stmt.executeQuery();
            
             if (rs.next()) {
                return rs.getBoolean("isAdmin");
             }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

}

public final class Server {
  
   private ServerSocket chatServerSocket;
   private final int chat; 
   private final int http;
   public static ArrayList<Handler> clients = new ArrayList<>(); //Array to store each client
   BlockingQueue<Runnable> workQueue = new SynchronousQueue<>();
   RejectedExecutionHandler rejectionHandler = new ThreadPoolExecutor.AbortPolicy(); // Throws RejectedExecutionException

   ExecutorService clientThreadPool = new ThreadPoolExecutor(
    0,
    10,
    0,
    TimeUnit.MILLISECONDS,
    workQueue,
    rejectionHandler
   );

   public Server(String webPort, String chatPort){
       this.chat = Integer.parseInt(chatPort);
       this.http = Integer.parseInt(webPort);
       this.chatServerSocket = null; 
       try{
         this.chatServerSocket = new ServerSocket(chat);
       }
       catch(IOException e){
         System.out.println("Error creating server socket");
         //e.printStackTrace();
       }
   }

   

   public void startUp (){
    try{
       WebHandler web = new WebHandler(http);
       Thread webThread = new Thread(web);
       webThread.start();
       chatServer(); //Nothing can go beyond this because it constantly waits for clients and will never end
       
    }
    catch(Exception e){
        System.out.println("Error starting server");
        //e.printStackTrace();
    }

   } 

   public static void csvWriter(String logPath, String userName, String message){
        try(PrintWriter pw = new PrintWriter(new FileWriter(logPath,true))){
           String timeStamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
           pw.println(timeStamp+","+userName+","+message);
           pw.flush();  
        }

        catch(Exception e){
              System.out.println("Error writing to log file");
              //e.printStackTrace();
        }

   }

   

   private void chatServer(){
       String timeStamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
       String programPath = Paths.get("").toAbsolutePath().toString();
       File logFolder = new File(programPath+"/logs");
       String logPath = (programPath+"/logs/Server Log Date-"+timeStamp+".csv");

       
        try{
           if (!logFolder.exists()) {
               if (logFolder.mkdirs()) {
                    System.out.println("Log folder created");
                    File logFile = new File(logPath);
                    logFile.createNewFile();
                } else {
                    System.out.println("Couldn't create log folder");
                }
           }
           else{
             File logFile = new File(logPath);
             logFile.createNewFile();
           }
           csvWriter(logPath, "SERVER", "SERVER START");
           
        }
        catch(Exception e){
            System.out.println("Error creating log file");
            //e.printStackTrace();
        }
           
        
        
           
        
        try{
          Packet noSpace = new Packet("SERVER", "No space in server");
          while(!chatServerSocket.isClosed()){ 

            Socket socket = chatServerSocket.accept(); //Program waits here until a client connects and creates a socket object so the program can be constantly waiting for a new client
            
            Handler client = new Handler(socket, logPath); 

            /*Normally the client would be added to the thread pool but if the exception throws it means the thread pool is full
            So it creates a new thread to send the message to the client and close it */
            try {
               clientThreadPool.submit(client);
            } catch (RejectedExecutionException e) {
                Thread tempThread = new Thread(() -> {
                   client.sendMessage(noSpace);
                   client.extCloser();  
                });
                tempThread.start();
                
            }
         }
        
        } catch (IOException e) {
         try {
             if (chatServerSocket != null){
                chatServerSocket.close(); //Closes the server if its open and something went wrong
             }
         } catch (IOException e2) {
                System.out.println("Error dealing with duplicate users connection");
                //e2.printStackTrace();  //For when the server was not open when failure occured
         }
        }
   }

   
   

public class Handler implements Runnable{
    
    private Socket socket;
    private String logPath;
    private ObjectInputStream packetInput;
    private ObjectOutputStream packetOutput;
    private Object receivedPacket;
    private String userName;
    private deffieHellman deffieHellman; 
    private byte[] key; 
    private boolean isClosed =false;
  

    
    
    public Handler(Socket socket, String logPath){
        try{
           this.socket = socket;
           this.logPath = logPath;
           this.packetOutput = new ObjectOutputStream(socket.getOutputStream());
           this.packetOutput.flush(); 
           this.packetInput = new ObjectInputStream(socket.getInputStream());

           //This block here is responsible for the key exchange 
           this.deffieHellman = new deffieHellman(); 
           this.packetOutput.writeObject(deffieHellman.encodePublicKey()); 
           this.packetOutput.flush();
           byte[] clientKeyBytes = (byte[]) packetInput.readObject(); 
           deffieHellman.setClientKey(clientKeyBytes);
           this.key = deffieHellman.getAESKey(); 
           

           
           this.receivedPacket = packetInput.readObject();
           this.userName = ((Packet)AESUtility.decryptObject ((byte[])receivedPacket, key)).getUsername();
           /* If a client with the same username already exists it must be a duplicate instance (because in the db usernames are unique) 
            This means the server has to boot off the duplicate to stop it from wasting space in the threadpool */
           
           boolean userNameExists = false;
           for (Handler client : Server.clients) {
              if (client.userName.equals(userName)) {
                  //Changes the name to duplicate user so people arent confused when they see the same name
                  userNameExists = true;
                  Packet alreadyConnected = new Packet("SEVER",userName+" has already conected");
                  this.userName = "Duplicate user"; 
                  sendMessage(alreadyConnected);
                  
                  Thread.sleep(1000);
                  System.out.println("User exists block");
                  closer(socket, packetInput, packetOutput);
                  break;
              }
            }

           if (!userNameExists){
              Server.clients.add(this);
              Packet joinPacket = new Packet("SERVER", userName+" has connected");
              sendMessage(joinPacket);
           }

        }
        catch(Exception e){
            System.out.println("Error in handler constructor");
            //e.printStackTrace();
            closer(socket, packetInput, packetOutput);
        }
        
    }

    public String getClientName(){
        return userName;
    }

    public byte[] getKey(){
        return key;
    }
    /*The send message method just iterates through a list of clients and sends the packet
     to each client except the one that sent it on top of that it logs the message */
    private void sendMessage (Packet packet){
        csvWriter(logPath, packet.getUsername(), packet.getMessage());
        System.out.println(packet.getUsername()+ ": " + packet.getMessage());
        for (Handler client : Server.clients){   
            try {
                if(!client.userName.equals(this.userName)){ 
                   byte[] encryptedPacket = AESUtility.encryptObject(packet, client.getKey());
                   client.packetOutput.writeObject(encryptedPacket);
                   client.packetOutput.flush();
                   
                }
            } 
            catch (Exception e) {
               System.out.println("Error sending message");
               //e.printStackTrace();
               closer(socket, packetInput, packetOutput);
            }
        }
    }

    private void dropClient(){
         //It is in an if statement so there arent duplicate leaving messages (Was a big problem when I was trying to stop duplicate users joining)
         if(!isClosed){
           Packet serverMessage = new Packet("SERVER", userName+" has left the chat");
           sendMessage(serverMessage);
           clients.remove(this);
           this.isClosed = true;
         }
    }

    private void closer(Socket socket, ObjectInputStream packetInput, ObjectOutputStream packetOutput){
        System.out.println("Closing resources for " + userName);
         //All this does is close the resources
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
             dropClient();
             
         }
         catch(IOException e){
             //e.printStackTrace();
             System.out.println("Error closing resources");
         }

    }

    private void extCloser(){
        System.out.println("The external closer is being used");
        closer(socket, packetInput, packetOutput);
    }


    


    @Override
    public void run(){
      //Waits for messages to come through because readObject is a blocker then it loops as long as the socket is connected
      try{
        while(socket.isConnected()){
            Object received = packetInput.readObject();
            if(received instanceof byte[]){
                Packet packet = (Packet) AESUtility.decryptObject ((byte[])received, key);
                sendMessage(packet);
            }
           
        }
      }
      catch(Exception e){
        //e.printStackTrace();
        System.out.println("Error in receiver");
        closer(socket, packetInput, packetOutput);
      }
    }
   }

   
                     

}

class Packet implements Serializable{

    private final String message;
    private final String username;
    private final String time;
    private final Date date;
    //Was going to include a date but it was not used in the end kept incase I develop further after I hand it in
    public Packet(String username, String message){
        this.date = new Date(); 
        this.time = String.format("%tT", date); 
        this.username = username;
        this.message = message;
      }

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
class deffieHellman {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey clientKey;
    private byte[] sharedSecret;

    /*Many methods in this class can experience NoSuchAlgorithmExceptions
     however the algorithms are hardcoded so there is no scenario where that exception occurs
     hence they just throw it.*/
     

    public deffieHellman () throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048); // Key size
        KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate(); 
        this.publicKey = keyPair.getPublic();
    }

    //Preps the public key to be sent to the client
    public byte[] encodePublicKey() {
        return publicKey.getEncoded();
    }

    //Receives and handles the public key
    public void setClientKey(byte[] clientKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientKeyBytes);
        this.clientKey = keyFactory.generatePublic(keySpec);
        generateSecretKey(); //Moves straight to generating the secret key no need to call seperatly
    }

    //Creates the secret key
    private void generateSecretKey()throws Exception{
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(clientKey, true);
        this.sharedSecret = keyAgreement.generateSecret();
    }

    //Preps key for use in AES
    public byte[] getAESKey()throws Exception{
         MessageDigest hashAlgo = MessageDigest.getInstance("SHA-256");
         byte[] aesKey = hashAlgo.digest(sharedSecret);
         //System.out.println("AES Key (Hex): " + bytesToHex(aesKey));
         System.out.println("AES Key Length: " + aesKey.length + " bytes");
         return aesKey;
    }

}
class AESUtility {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    //private static final byte[] KEY = "CryptKey98473817".getBytes(); //Dont hardcode
    

    public static byte[] encryptObject(Serializable object, byte[] key) throws Exception {
        //Turns the object into bytes
        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
        objectOutput.writeObject(object);
        objectOutput.flush();
        byte[] byteObject = byteOutput.toByteArray();
        
        //Encrypt
        Key secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(byteObject);
    }
    
    public static Object decryptObject(byte[] encryptedBytes,byte[] key) throws Exception {
        //Decrypt
        Key secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] byteObject = cipher.doFinal(encryptedBytes);
        
        //Puts the bytes back into an object
        ByteArrayInputStream byteInput = new ByteArrayInputStream(byteObject);
        ObjectInputStream objectInput = new ObjectInputStream(byteInput);
        return objectInput.readObject();
    }
}

class WebHandler implements Runnable{

    private int port;

    WebHandler(int port){
        this.port=port;
    }

    private String formatTime(int secs){
           int mins = secs/60;
           int hrs = mins/60;
           int days = hrs/24;

           return ("Days:"+days+" Hours:"+hrs+" Mins"+mins+" Secs:"+secs);

    }

    @Override
    public void run(){
        ExecutorService threadPool = Executors.newCachedThreadPool();
        Thread.setDefaultUncaughtExceptionHandler((Thread t, Throwable e) -> {
            //e.printStackTrace();
            System.out.println("Exception in thread");
        });
        int serverStartTime = (int)System.currentTimeMillis()/1000;
        try{
           HttpServer server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
           server.createContext("/", new HttpHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    StringBuilder htmlResponse = new StringBuilder();
                    htmlResponse.append("<html><body><head><h1>Java server stats</h1></head>" +
                    "<h2>Connected users:</h2>");
                    htmlResponse.append("<ul>");

                    for(int i = 0; i < Server.clients.size(); i++){
                        String clientName = (Server.clients.get(i)).getClientName();
                        htmlResponse.append("<li>"+clientName+"</li>");
                    } 

                    htmlResponse.append("</ul>");

                    int uptimeMillis = ((int)System.currentTimeMillis()/1000) - serverStartTime;
                    String uptime = formatTime(uptimeMillis);
                    htmlResponse.append("<h2>Server Uptime:</h2>");
                    htmlResponse.append("<p>").append(uptime).append("</p>");

                    OperatingSystemMXBean bean = (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
                    double cpuUsage = (bean.getProcessCpuLoad())*100;
                    htmlResponse.append("<h2>CPU Usage:</h2>");
                    htmlResponse.append("<p>").append(String.format("%.2f%%", cpuUsage)).append("</p>");


                    Runtime runtime = Runtime.getRuntime();
                    long usedMemory = runtime.totalMemory() - runtime.freeMemory();
                    long maxMemory = runtime.maxMemory();
                    htmlResponse.append("<h2>Memory Usage:</h2>");
                    htmlResponse.append("<p>Used: ").append(usedMemory / (1024 * 1024)).append(" MB</p>");
                    htmlResponse.append("<p>Max: ").append(maxMemory / (1024 * 1024)).append(" MB</p>");




                    htmlResponse.append("</body></html>");

                    String finalResponse = htmlResponse.toString();
                    // Set the response headers
                    exchange.getResponseHeaders().set("Content-Type", "text/html");
                    exchange.sendResponseHeaders(200, finalResponse.length());
                    
                    // Write the HTML response
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(finalResponse.getBytes());
                    }
                }
            });
           server.setExecutor(threadPool);
           server.start();
           System.out.println("Web Server started on port " + port);
        }
        catch(IOException e){
            System.out.println("Error with web server");
            //e.printStackTrace();
        }
    }
}