package chatmultiple;

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javax.swing.JOptionPane;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Server4 extends javax.swing.JFrame {

    ArrayList clientOutputStreams;
    ArrayList<String> onlineUsers;
    static DataInputStream datain;
    static DataOutputStream dataout;

    File file;
    PrintWriter pw;
    private static final String ALGO = "AES";
    private static final byte[] keyValue
            = new byte[]{'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};

    String encryptpassword(String in) {

        String passwordToHash = in;
        String generatedPassword = null;
        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            //Add password bytes to digest
            md.update(passwordToHash.getBytes());
            //Get the hash's bytes
            byte[] bytes = md.digest();
            //This bytes[] has bytes in decimal format;
            //Convert it to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            //Get complete hashed password in hex format
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    public static String encrypt(String Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    public static String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    private static Key generateKey() throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGO);
        return key;
    }

    public class ClientHandler implements Runnable {

        BufferedReader reader;
        Socket sock;
        PrintWriter client;

        public ClientHandler(Socket clientSocket, PrintWriter user) {
            // new inputStreamReader and then add it to a BufferedReader
            client = user;
            try {
                sock = clientSocket;
                InputStreamReader isReader = new InputStreamReader(sock.getInputStream());
                reader = new BufferedReader(isReader);
            } // end try
            catch (Exception ex) {
                outputPane.append("Error beginning StreamReader. \n");
            } // end catch

        } // end ClientHandler()

        public void run() {
            String message, connect = "Connect", disconnect = "Disconnect", chat = "Chat";
            String[] data;

            try {
                while ((message = reader.readLine()) != null) {
                    //   System.out.println(message+"");
                    message = decrypt(message);
                    data = message.split(":");
                    outputPane.append("Received: " + data[0] + ":" + data[2] + ":" + data[3] + "\n");

                    for (String token : data) {

                        outputPane.append(token + "\n");

                    }

                    if (data[3].equals(connect)) {

                        tellEveryone((data[0] + ":" + data[1] + ":" + data[2] + ":" + chat));
                        userAdd(data[0]);

                    } else if (data[3].equals(disconnect)) {

                        tellEveryone((data[0] + ":" + data[1] + ":has disconnected." + ":" + chat));

                        userRemove(data[0]);

                    } else if (data[3].equals(chat)) {

                        tellEveryone(message);

                    } else {
                        outputPane.append("No Conditions were met. \n");
                    }

                } // end while
            } // end try
            catch (Exception ex) {
                outputPane.append("Lost a connection. \n");

                ex.printStackTrace();
                clientOutputStreams.remove(client);
            } // end catch
        } // end run()
    } // end class ClientHandler

    public Server4() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        outputPane = new javax.swing.JTextArea();
        startButton = new javax.swing.JButton();
        stopButton = new javax.swing.JButton();
        usernameField1 = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        register = new javax.swing.JButton();
        passwordField1 = new javax.swing.JPasswordField();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        outputPane.setEditable(false);
        outputPane.setColumns(20);
        outputPane.setRows(5);
        jScrollPane1.setViewportView(outputPane);

        getContentPane().add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 44, 389, 455));

        startButton.setText("START SERVER");
        startButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                startButtonActionPerformed(evt);
            }
        });
        getContentPane().add(startButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 521, 157, 54));

        stopButton.setText("STOP SERVER");
        stopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                stopButtonActionPerformed(evt);
            }
        });
        getContentPane().add(stopButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(219, 521, 140, 54));
        getContentPane().add(usernameField1, new org.netbeans.lib.awtextra.AbsoluteConstraints(560, 270, 171, -1));

        jLabel1.setText("Username : ");
        getContentPane().add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(470, 270, -1, -1));

        jLabel2.setText("Password:");
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(470, 300, -1, -1));

        register.setText("Register");
        register.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                registerActionPerformed(evt);
            }
        });
        getContentPane().add(register, new org.netbeans.lib.awtextra.AbsoluteConstraints(600, 340, -1, -1));
        getContentPane().add(passwordField1, new org.netbeans.lib.awtextra.AbsoluteConstraints(560, 300, 171, -1));

        jLabel5.setFont(new java.awt.Font("Comic Sans MS", 3, 18)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(187, 3, 3));
        jLabel5.setText("New User Registration:");
        getContentPane().add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(530, 240, -1, -1));

        jLabel6.setFont(new java.awt.Font("Comic Sans MS", 3, 18)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(187, 3, 3));
        jLabel6.setText("Server Information :");
        getContentPane().add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 12, -1, -1));
        getContentPane().add(jLabel7, new org.netbeans.lib.awtextra.AbsoluteConstraints(335, 0, 474, 38));

        jLabel8.setIcon(new javax.swing.ImageIcon(getClass().getResource("/chatmultiple/register icon.png"))); // NOI18N
        getContentPane().add(jLabel8, new org.netbeans.lib.awtextra.AbsoluteConstraints(540, 50, -1, 182));

        jLabel9.setIcon(new javax.swing.ImageIcon(getClass().getResource("/chatmultiple/server-background.jpg"))); // NOI18N
        jLabel9.setText("jLabel9");
        getContentPane().add(jLabel9, new org.netbeans.lib.awtextra.AbsoluteConstraints(190, -20, 730, 610));

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void startButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_startButtonActionPerformed
        // TODO add your handling code here:
        // TODO add your handling code here:

        Thread starter = new Thread(new ServerStart());
        starter.start();

        outputPane.append("Server started. \n");
    }//GEN-LAST:event_startButtonActionPerformed

    private void stopButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_stopButtonActionPerformed
        // TODO add your handling code here:
        tellEveryone("Server:is stopping and all users will be disconnected.\n:Chat");
        outputPane.append("Server stopping... \n");

    }//GEN-LAST:event_stopButtonActionPerformed
    static int contains(String username, String password) throws FileNotFoundException {

        File file = new File("data.txt");
        int p = -1;
        Scanner sc = new Scanner(file);
        while (sc.hasNext()) {
            String ab = sc.nextLine();
            String check[] = ab.split(":");
            check[0] = check[0].trim();
            check[1] = check[1].trim();
            if (check[0].compareTo(username) == 0) {
                if (check[1].compareTo(password) == 0) {
                    p = 1;
                    break;
                } else {
                    p = 0;
                    break;
                }
            }
        }
        return p;
    }

    int search(String username) throws FileNotFoundException {
        File file = new File("data.txt");
        int p = -1;
        Scanner sc = new Scanner(file);
        while (sc.hasNext()) {
            String ab = sc.nextLine();
            String check[] = ab.split(":");
            check[0] = check[0].trim();
            if (check[0].compareTo(username) == 0) {
                return 1;
            }
        }
        return 0;
    }

    private void registerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_registerActionPerformed
        String username = usernameField1.getText().trim();
        String password = passwordField1.getText().trim();

        try {
            // TODO add your handling code here:
            if (!username.equals("") && !password.equals("")) {
                if (search(username) == 0) {
                    File file = new File("data.txt");
                    FileWriter fw = new FileWriter(file, true);
                    BufferedWriter bw = new BufferedWriter(fw);
                    PrintWriter pw = new PrintWriter(bw);
                    pw.println(username + ":" + encryptpassword(password));
                    pw.close();

                    JOptionPane.showMessageDialog(null, "Registered Successfully!!!");
                } else {
                    JOptionPane.showMessageDialog(null, "Username Already Exists!!!");
                }
            } else {
                JOptionPane.showMessageDialog(null, "Username or Password Can't be null!!!");
            }
        } catch (Exception e) {
        }
        usernameField1.setText("");
        passwordField1.setText("");
    }//GEN-LAST:event_registerActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {

        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Server4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Server4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Server4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Server4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Server4().setVisible(true);

            }
        });
    }

    public class ServerStart implements Runnable {

        public void running(Socket clientSock) throws IOException {
            datain = new DataInputStream(clientSock.getInputStream());
            dataout = new DataOutputStream(clientSock.getOutputStream());
            String msgin = "";
            while (msgin.length() == 0) {
                msgin = datain.readUTF();
            }

            String arr[] = msgin.split(":");
            int p = contains(arr[0], arr[1]);

            String msgout = "";
            msgout += String.valueOf(p);

            dataout.writeUTF(msgout);
        }

        public void run() {
            clientOutputStreams = new ArrayList();
            onlineUsers = new ArrayList();

            try {
                ServerSocket serverSock = new ServerSocket(8000);

                while (true) {
                    // set up the server writer function and then begin at the same
                    // the listener using the Runnable and Thread
                    Socket clientSock = serverSock.accept();
                    running(clientSock);

                    PrintWriter writer = new PrintWriter(clientSock.getOutputStream());
                    clientOutputStreams.add(writer);

                    // use a Runnable to start a 'second main method that will run
                    // the listener
                    Thread listener = new Thread(new ClientHandler(clientSock, writer));
                    listener.start();

                    outputPane.append("Got a connection. \n");
                } // end while
            } // end try
            catch (Exception ex) {
                outputPane.append("Error making a connection. \n");
            } // end catch

        } // end go()
    }

    void listtofile(ArrayList<String> ab) throws IOException {

        FileWriter fw = new FileWriter("online.txt");
        BufferedWriter bw = new BufferedWriter(fw);
        for (String token : ab) {
            bw.write(token);
            bw.newLine();

        }
        bw.close();
    }

    public void userAdd(String data) throws IOException {
        String message, add = ": :  :Connect", done = "Server: : :Done", name = data;
        outputPane.append("Before " + name + " added. \n");
        onlineUsers.add(name);

        outputPane.append("After " + name + " added. \n");
        String[] tempList = new String[(onlineUsers.size())];
        onlineUsers.toArray(tempList);

        for (String token : tempList) {

            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    public void userRemove(String data) throws IOException {
        String message, add = ": : :Connect", done = "Server: : :Done", name = data;
        onlineUsers.remove(name);
        /*   PrintWriter wr;
         try {
         wr = new PrintWriter("online.txt");
         wr.print("");
         wr.close();
         } catch (Exception e) {
         }*/
        System.out.println("cleared");
        //     listtofile(onlineUsers);
        System.out.println(onlineUsers);

        String[] tempList = new String[(onlineUsers.size())];
        onlineUsers.toArray(tempList);

        for (String token : tempList) {

            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    public void tellEveryone(String message) {
        // sends message to everyone connected to server
        Iterator it = clientOutputStreams.iterator();

        while (it.hasNext()) {
            try {
                PrintWriter writer = (PrintWriter) it.next();
                writer.println(encrypt(message));
                String[] data = message.split(":");
                outputPane.append("Sending: " + data[0] + ":" + data[2] + ":" + data[3] + "\n");

                writer.flush();
                outputPane.setCaretPosition(outputPane.getDocument().getLength());

            } // end try
            catch (Exception ex) {
                outputPane.append("Error telling everyone. \n");
            } // end catch
        } // end while
    } // end tellEveryone()

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea outputPane;
    private javax.swing.JPasswordField passwordField1;
    private javax.swing.JButton register;
    private javax.swing.JButton startButton;
    private javax.swing.JButton stopButton;
    private javax.swing.JTextField usernameField1;
    // End of variables declaration//GEN-END:variables
}
