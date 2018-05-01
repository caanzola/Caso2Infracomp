import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator 
{

	private LoadGenerator generator;
	public static int transaccionesPerdidas;
	private ArrayList<Long> tiemposRespuesta;
	private ArrayList<Long> tiempoLlave;
	private ArrayList<Cliente> clientes;
	
	public Generator()
	{



		tiemposRespuesta = new ArrayList<Long>();
		tiempoLlave = new ArrayList<Long>();
		clientes = new ArrayList<Cliente>();
		
		transaccionesPerdidas = 0;
		Task work = createTask();
		int numeroTareas = 200;
		int tiempoEntreTareas = 40;
		generator = new LoadGenerator("Cliente - servidor, prueba de carga", numeroTareas, work, tiempoEntreTareas);
		generator.generate();
		System.out.println("Número de transacciones perdidas " + transaccionesPerdidas);
//		generarArchivo();
	}
	
	public Generator darGenerator(){
		return this;
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
	
	public void agregarTRespuesta(Long t){
		tiemposRespuesta.add(t);
	}
	
	public void agregarTLlave(Long t){
		tiempoLlave.add(t);
	}
	
	public void agregarCliente(Cliente cliente){
		clientes.add(cliente);
		
	}
}
