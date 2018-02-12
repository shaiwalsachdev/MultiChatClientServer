/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatmultiple;

import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Client4 extends javax.swing.JFrame {

    String username, serverIP;
    static DataInputStream datain;
    static DataOutputStream dataout;
    String password;
    int Port = 8000;
    Socket sock;
    BufferedReader reader;
    PrintWriter writer;
    PrintWriter pw;
    private static final String ALGO = "AES";
    private static final byte[] keyValue = new byte[]{'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};

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

    Boolean isConnected = false;

    public Client4() {

        initComponents();
    }

    public class IncomingReader implements Runnable {

        public void run() {
            String[] data;
            String stream, done = "Done", connect = "Connect", disconnect = "Disconnect", chat = "Chat";

            try {
                while ((stream = reader.readLine()) != null) {
                    stream = decrypt(stream);
                    data = stream.split(":");
                    
                    if (data[3].equals(chat)) {

                        chatTextArea.append(data[0] + ": " + data[2] + "\n");
                        chatTextArea.setCaretPosition(chatTextArea.getDocument().getLength());

                    } else if (data[3].equals(connect)) {

                        chatTextArea.removeAll();
                        

                    } else if (data[3].equals(disconnect)) {
                        userRemove(data[0]);
                     

                    } else if (data[3].equals(done)) {

                        usersList.setText("");
                    
                        writeUsers();
                
                    }

                }
            } catch (Exception ex) {
            }
        }
    }

    public void ListenThread() {
        Thread IncomingReader = new Thread(new IncomingReader());
        IncomingReader.start();
    }

    public void userAdd(String data, String pass) throws FileNotFoundException, IOException {
        
        File file = new File("data.txt");
        FileWriter fw = new FileWriter(file, true);
        BufferedWriter bw = new BufferedWriter(fw);
        PrintWriter pw = new PrintWriter(bw);
        pw.println(data + ":" + pass);
        pw.close();
    }

    public void userRemove(String data) {
        chatTextArea.append(data + " has disconnected.\n");

    }

    public void writeUsers() throws FileNotFoundException {

        File file = new File("data.txt");
        Scanner sc = new Scanner(file);
        while (sc.hasNext()) {
            usersList.append((sc.nextLine().split(":")[0]).trim() + "\n");
        }
    }

    

    public void sendDisconnect() {

        String bye = (username + ": :Disconnect");
        try {
            writer.println(encrypt(bye)); // Sends server the disconnect signal.
            writer.flush(); // flushes the buffer
        } catch (Exception e) {
            chatTextArea.append("Could not send Disconnect message.\n");
        }

    }

    public void Disconnect() {

        try {
            chatTextArea.append("Disconnected.\n");
            JOptionPane.showMessageDialog(null, "See You Soon!!!");
            sock.close();
        } catch (Exception ex) {
            chatTextArea.append("Failed to disconnect. \n");
        }
        isConnected = false;
        usernameField.setEditable(true);
        passwordField.setEditable(true);
        usersList.setText("");
     //   onlineList.setText("");

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel2 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        connectButton = new javax.swing.JButton();
        disconnectButton = new javax.swing.JButton();
        usernameField = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        usersList = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        chatTextArea = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        inputTextArea = new javax.swing.JTextArea();
        sendButton = new javax.swing.JButton();
        passwordField = new javax.swing.JPasswordField();
        jLabel3 = new javax.swing.JLabel();
        ipp = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel2.setText("Password:");
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(210, 50, -1, -1));

        jLabel1.setText("Username : ");
        getContentPane().add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(210, 10, -1, -1));

        connectButton.setText("Chat");
        connectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });
        getContentPane().add(connectButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(510, 20, 121, 45));

        disconnectButton.setText("GoodBye");
        disconnectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disconnectButtonActionPerformed(evt);
            }
        });
        getContentPane().add(disconnectButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(680, 80, 140, 60));

        usernameField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                usernameFieldActionPerformed(evt);
            }
        });
        getContentPane().add(usernameField, new org.netbeans.lib.awtextra.AbsoluteConstraints(310, 10, 154, -1));

        usersList.setEditable(false);
        usersList.setColumns(20);
        usersList.setRows(5);
        jScrollPane1.setViewportView(usersList);

        getContentPane().add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(830, 200, 165, 236));

        chatTextArea.setEditable(false);
        chatTextArea.setColumns(20);
        chatTextArea.setRows(5);
        jScrollPane2.setViewportView(chatTextArea);

        getContentPane().add(jScrollPane2, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 150, 820, 380));

        inputTextArea.setColumns(20);
        inputTextArea.setRows(5);
        inputTextArea.setText("Write Your Message Here..............");
        inputTextArea.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                inputTextAreaMouseClicked(evt);
            }
        });
        inputTextArea.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                inputTextAreaKeyTyped(evt);
            }
        });
        jScrollPane3.setViewportView(inputTextArea);

        getContentPane().add(jScrollPane3, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 540, 830, 76));

        sendButton.setText("SEND");
        sendButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendButtonActionPerformed(evt);
            }
        });
        getContentPane().add(sendButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(850, 550, 140, 55));
        getContentPane().add(passwordField, new org.netbeans.lib.awtextra.AbsoluteConstraints(310, 50, 154, -1));

        jLabel3.setText("IP Address:");
        getContentPane().add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(210, 90, -1, -1));
        getContentPane().add(ipp, new org.netbeans.lib.awtextra.AbsoluteConstraints(310, 90, 160, 30));

        jLabel4.setFont(new java.awt.Font("Comic Sans MS", 3, 18)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(226, 21, 21));
        jLabel4.setText("LOGIN");
        getContentPane().add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(140, 10, 70, 60));

        jLabel5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/chatmultiple/chat-2-icon.png"))); // NOI18N
        jLabel5.setText("jLabel5");
        getContentPane().add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 0, 270, 250));

        jLabel8.setFont(new java.awt.Font("Ubuntu", 1, 15)); // NOI18N
        jLabel8.setText("Registered Users:");
        getContentPane().add(jLabel8, new org.netbeans.lib.awtextra.AbsoluteConstraints(850, 180, -1, -1));

        jLabel6.setIcon(new javax.swing.ImageIcon(getClass().getResource("/chatmultiple/social_media_speaker_hd_wallpapers-1024x640.png"))); // NOI18N
        getContentPane().add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 1020, -1));

        pack();
    }// </editor-fold>//GEN-END:initComponents
    public void sendbuttonwork() {
        String nothing = "";
        if ((inputTextArea.getText()).equals(nothing)) {
            inputTextArea.setText("");
            inputTextArea.requestFocus();
        } else {
            try {

                writer.println(encrypt(username + ":" + password + ":" + inputTextArea.getText() + ":" + "Chat"));
                writer.flush(); // flushes the buffer
            } catch (Exception ex) {
                chatTextArea.append("Message was not sent. \n");
            }
            inputTextArea.setText("");
            inputTextArea.requestFocus();
        }

        inputTextArea.setText("");
        inputTextArea.requestFocus();

    }


    private void sendButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendButtonActionPerformed
        // TODO add your handling code here:
        sendbuttonwork();

    }//GEN-LAST:event_sendButtonActionPerformed
    

    private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed
        String msgout = "";
        String msgin = "";
        serverIP = ipp.getText();
        int p = -1;
        try {
            sock = new Socket(serverIP, Port);
            datain = new DataInputStream(sock.getInputStream());
            dataout = new DataOutputStream(sock.getOutputStream());

            username = usernameField.getText().trim();
            password = passwordField.getText().trim();
            msgout = username + ":" + encryptpassword(password);
            dataout.writeUTF(msgout);
       

            while (msgin.length() == 0) {
                msgin = datain.readUTF();
            }
     

        } catch (Exception e) {
        }

        if (!username.equals("") && !password.equals("") &&!serverIP.equals("")) {
            usernameField.setEditable(false);
            passwordField.setEditable(false);
            
            p = Integer.parseInt(msgin);

            //  System.out.println(p);
            if (p != -1) {

                if (p == 1) {
                    JOptionPane.showMessageDialog(null, "Logged In successfully!!!");
                    if (isConnected == false) {
                        try {
                  //      sock = new Socket(serverIP, Port);

                            InputStreamReader streamreader = new InputStreamReader(sock.getInputStream());
                            reader = new BufferedReader(streamreader);
                            writer = new PrintWriter(sock.getOutputStream());
                            //    System.out.println(username + ":"+password+":has connected.:Connect");
                            writer.println(encrypt(username + ":" + password + ":has connected.:Connect")); // Displays to everyone that user connected.
                            writer.flush(); // flushes the buffer
                            isConnected = true; // Used to see if the client is connected.
                            chatTextArea.append("Welcome to CODE CHAT MESSENGER  " + username + "\n");
                            chatTextArea.append("Enjoy !! " + username + "\n");
                        } catch (Exception ex) {
                            chatTextArea.append("Cannot Connect! Try Again. \n");
                            usernameField.setEditable(true);
                            passwordField.setEditable(true);
                        }
                        ListenThread();
                    } else if (isConnected == true) {
                        chatTextArea.append("You are already connected. \n");
                    }

                }
                if (p == 0) {
                    JOptionPane.showMessageDialog(null, "Wrong Password Try Again!!");
                    usernameField.setEditable(true);
                    passwordField.setEditable(true);
                }
            } else {
                JOptionPane.showMessageDialog(null, "Username Doesn't Exist!!!");
                usernameField.setEditable(true);
                passwordField.setEditable(true);
            }

        } else {
            JOptionPane.showMessageDialog(null, "Username or Password  or IP can't be null !!!");
            usernameField.setEditable(true);
            passwordField.setEditable(true);
        }
        usernameField.setText("");
        passwordField.setText("");
        ipp.setText("");
    }//GEN-LAST:event_connectButtonActionPerformed

    private void disconnectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnectButtonActionPerformed
        // TODO add your handling code here:
        sendDisconnect();
        Disconnect();
        chatTextArea.setText("");

    }//GEN-LAST:event_disconnectButtonActionPerformed

    private void usernameFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_usernameFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_usernameFieldActionPerformed

    private void inputTextAreaKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_inputTextAreaKeyTyped
        char k = evt.getKeyChar();

        if (k == KeyEvent.VK_ENTER) {
            sendbuttonwork();
        }

    }//GEN-LAST:event_inputTextAreaKeyTyped

    private void inputTextAreaMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_inputTextAreaMouseClicked
        // TODO add your handling code here:
        inputTextArea.setText("");
    }//GEN-LAST:event_inputTextAreaMouseClicked

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
            java.util.logging.Logger.getLogger(Client4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Client4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Client4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Client4.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
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

                new Client4().setVisible(true);

            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea chatTextArea;
    private javax.swing.JButton connectButton;
    private javax.swing.JButton disconnectButton;
    private javax.swing.JTextArea inputTextArea;
    private javax.swing.JTextField ipp;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JPasswordField passwordField;
    public javax.swing.JButton sendButton;
    private javax.swing.JTextField usernameField;
    private javax.swing.JTextArea usersList;
    // End of variables declaration//GEN-END:variables
}
