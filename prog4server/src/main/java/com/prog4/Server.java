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
import javax.crypto.spec.SecretKeySpec;

import com.sun.management.OperatingSystemMXBean;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;


public final class Server {
  
   private final ServerSocket chatServerSocket;
   public static ArrayList<Handler> clients = new ArrayList<>(); //Array to store each client
   BlockingQueue<Runnable> workQueue = new SynchronousQueue<>();
   RejectedExecutionHandler rejectionHandler = new ThreadPoolExecutor.AbortPolicy(); // Throws RejectedExecutionException

   ExecutorService clientThreadPool = new ThreadPoolExecutor(
    0,
    2,
    0,
    TimeUnit.MILLISECONDS,
    workQueue,
    rejectionHandler
   );

   private Server(ServerSocket chatServerSocket){
       this.chatServerSocket=chatServerSocket;
   }

   

   public static void main (String[] args){
    try{
       ServerSocket chatServerSocket = new ServerSocket(7777);
       int webServerSocket = 8080;
       Server Server = new Server(chatServerSocket);
       WebHandler web = new WebHandler(webServerSocket);
       Thread webThread = new Thread(web);
       webThread.start();
       Server.chatServer(); //Nothing goes beyond this because it constantly waits for clients
       
    }
    catch(Exception e){
        e.printStackTrace();
    }

   } 

   public static void csvWriter(String logPath, String userName, String message){
        try(PrintWriter pw = new PrintWriter(new FileWriter(logPath,true))){
           String timeStamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
           pw.println(timeStamp+","+userName+","+message);
           pw.flush();  
        }

        catch(Exception e){
              e.printStackTrace();
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
            e.printStackTrace();
        }
           
        
        
           
        
        try{
          Packet noSpace = new Packet("SERVER", "No space in server");
          while(!chatServerSocket.isClosed()){ //Loops as long as the socket is open

            Socket socket = chatServerSocket.accept(); //Program waits here until a client connects and creates a socket object
            
            Handler client = new Handler(socket, logPath); //Creates new client object using the socket

            try {
               clientThreadPool.submit(client);
            } catch (RejectedExecutionException e) {
                // Handle full pool case
                Thread tempThread = new Thread(() -> {
                   client.sendMessage(noSpace);
                   client.extCloser();  // Close after sending
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
            e2.printStackTrace();  //Throws error if server was not open when failure occured
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

    
    
    public Handler(Socket socket, String logPath){
        try{
           this.socket = socket;
           this.logPath = logPath;
           this.packetOutput = new ObjectOutputStream(socket.getOutputStream());
           this.packetOutput.flush(); 
           this.packetInput = new ObjectInputStream(socket.getInputStream());
           this.receivedPacket = packetInput.readObject();
           
           this.userName = ((Packet)AESUtility.decryptObject ((byte[])receivedPacket)).getUsername();
           
           Server.clients.add(this);
           Packet joinPacket = new Packet("SERVER", userName+" has connected");
           sendMessage(joinPacket);

           
           
        

        }
        catch(Exception e){
            closer(socket, packetInput, packetOutput);
        }
        
    }

    public String getClientName(){
        return userName;
    }
    
    private void sendMessage (Packet packet){
        csvWriter(logPath, packet.getUsername(), packet.getMessage());
        System.out.println(packet.getUsername()+ ": " + packet.getMessage());
        for (Handler client : Server.clients){   //Iterates through each connected client to send them the message
            try {
                if(!client.userName.equals(this.userName)){ //Runs if the username isnt the same (only sends to other people)
                   byte[] encryptedPacket = AESUtility.encryptObject(packet);
                   client.packetOutput.writeObject(encryptedPacket);
                   client.packetOutput.flush();
                   
                }
            } 
            catch (Exception e) {
               e.printStackTrace();
               closer(socket, packetInput, packetOutput);
            }
        }
    }

    private void dropClient(){
           Packet serverMessage = new Packet("SERVER", userName+" has left the chat");
           sendMessage(serverMessage);
           clients.remove(this);
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
             dropClient();
         }
         catch(IOException e){
             e.printStackTrace();
         }

    }

    private void extCloser(){
        closer(socket, packetInput, packetOutput);
    }


    


    @Override
    public void run(){
      try{
        while(socket.isConnected()){
            Object received = packetInput.readObject();
            if(received instanceof byte[]){
                Packet packet = (Packet) AESUtility.decryptObject ((byte[])received);
                sendMessage(packet);
            }
           
        }
      }
      catch(Exception e){
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

    //Constructor 
    public Packet(String username, String message){
        this.date = new Date(); 
        this.time = String.format("%tT", date); 
        this.username = username;
        this.message = message;
      }

    //Getters (No setters to prevent changes before object is sent)
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
            e.printStackTrace();
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
            e.printStackTrace();
        }
    }
}