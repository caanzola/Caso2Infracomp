import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator 
{

	private LoadGenerator generator;
	
	public Generator()
	{
		Task work = createTask();
		int numeroTareas = 100;
		int tiempoEntreTareas = 1000;
		generator = new LoadGenerator("Cliente - servidor, prueba de carga", numeroTareas, work, tiempoEntreTareas);
		generator.generate();
	}
	
	private Task createTask()
	{
		return new ClientServerTask();
	}
	
	public static void main(String[] args) 
	{
		Generator gen = new Generator();
	}
	
}
