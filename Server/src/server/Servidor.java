package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {
	private static final int TIME_OUT = 100000;
	public static final int N_THREADS = 2;
	private static ServerSocket elSocket;
	private static Servidor elServidor;
	public static int transaccionesPerdidas;

	public Servidor() {
	}

	private ExecutorService executor = Executors.newFixedThreadPool(N_THREADS);

	public static void main(String[] args) throws IOException {
		transaccionesPerdidas=0;
		elServidor = new Servidor();
		elServidor.runServidor();
	}

	private void runServidor() {
		int num = 0;
		try {
			System.out.print("Puerto: ");
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			int puerto = Integer.parseInt(br.readLine());
			elSocket = new ServerSocket(puerto);
			System.out.println("Servidor escuchando en puerto: " + puerto);
			for (;;) {
				Socket sThread = null;

				sThread = elSocket.accept();
				sThread.setSoTimeout(TIME_OUT);
				System.out.println("Thread " + num + " recibe a un cliente.");
				executor.submit(new Worker(num, sThread, this));
				num++;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public synchronized void aumentarPerdidas()
	{
		transaccionesPerdidas++;
		System.out.println("N�mero de transacciones perdidas: " + transaccionesPerdidas);
		System.out.println();
	}

	public void informarTransaccionesPerdidas() 
	{
		System.out.println("N�mero de transacciones perdidas: " + transaccionesPerdidas);
		System.out.println();
	}
}
