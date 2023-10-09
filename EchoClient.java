import java.io.*;
import java.net.*;

public class EchoClient {
    DatagramSocket socket;

    String ping(String hostname, int port, String msg) throws UnknownHostException, IOException {
        byte[] buf = msg.getBytes();
        byte[] recvbuf = new byte[256];
        InetAddress address = InetAddress.getByName(hostname);
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
        socket.send(packet);
        packet = new DatagramPacket(recvbuf, recvbuf.length);
        socket.receive(packet);
        String received = new String(packet.getData(), 0, packet.getLength());
        return received;
    }

    public static void main(String[] args) throws IOException {
        new EchoClient().run(args);
    }

    private void run(String[] args) {
        if (args.length != 2) {
            System.err.println(
                    "Usage: java EchoClient <host name> <port number>");
            System.exit(1);
        }

        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);

        try {
            socket = new DatagramSocket();
            for (int i = 0; i < 10; i++) {
                String ans = ping(hostName, portNumber, "hello " + i);
                System.out.println("Received: " + ans);
            }
        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            System.exit(1);
        }
    }
}
