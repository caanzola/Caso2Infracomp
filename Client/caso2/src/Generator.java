import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator 
{

	private LoadGenerator generator;
	public static int transaccionesPerdidas;
	
	public Generator()
	{
		transaccionesPerdidas = 0;
		Task work = createTask();
		int numeroTareas = 4;
		int tiempoEntreTareas = 1000;
		generator = new LoadGenerator("Cliente - servidor, prueba de carga", numeroTareas, work, tiempoEntreTareas);
		generator.generate();
		System.out.println("Número de transacciones perdidas " + transaccionesPerdidas);
	}
	
	private Task createTask()
	{
		return new ClientServerTask(this);
	}
	
	public static void main(String[] args) 
	{
		Generator gen = new Generator();
	}
	
	public void aumentarPerdidas()
	{
		transaccionesPerdidas++;
	}
	
}
