import java.io.FileOutputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;

import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;

import uniandes.gload.core.Task;

public class ClientServerTask extends Task
{
	private Generator gen;
	private ArrayList<Cliente> clientes;
	HSSFWorkbook workbook;
	HSSFSheet sheet;
	HSSFRow rowhead; 
	int cont = 1;
	String filename = "./data/resultados.xls" ;
   
	
	public ClientServerTask (Generator generator)
	{
		gen = generator;
		clientes = new ArrayList<Cliente>();
		workbook = new HSSFWorkbook();
		sheet = workbook.createSheet("FirstSheet");  
		rowhead = sheet.createRow((short)0);
		rowhead.createCell(1).setCellValue("tiempo respuesta");
        rowhead.createCell(2).setCellValue("Tiempo lave simetrica");
	}
	
	@Override
	public void execute()
	{
		try 
		{
			Cliente cliente = new Cliente();
			gen.agregarTLlave(cliente.darTLlaveS());
			gen.agregarTRespuesta(cliente.darTActualizacion());
//			System.out.println("Se va a agregar un cliente con tempos: " + cliente.darTActualizacion() + ", " + cliente.darTLlaveS());
//			gen.agregarCliente(cliente);
			HSSFRow rowheadN = sheet.createRow((short)cont);
			rowheadN.createCell(0).setCellValue(cont);
        	rowheadN.createCell(1).setCellValue(cliente.darTActualizacion());
            rowheadN.createCell(2).setCellValue(cliente.darTLlaveS());
			success();
			cont++;
		} 
		catch (Exception e) 
		{
			gen.aumentarPerdidas();
			fail();
		} 
		try {
        	FileOutputStream fileOut = new FileOutputStream(filename);
			workbook.write(fileOut);
			fileOut.close();
			workbook.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void generarArchivo(){
		System.out.println("Se va a generar el archivo, hay una lista con " + clientes.size() + " clientes");
		String filename = "./data/resultados.xls" ;
        HSSFWorkbook workbook = new HSSFWorkbook();
        HSSFSheet sheet = workbook.createSheet("FirstSheet");  
    	HSSFRow rowhead = sheet.createRow((short)0);

        rowhead.createCell(0).setCellValue("tiempo respuesta");
        rowhead.createCell(1).setCellValue("Tiempo lave simetrica");

        for(int i = 1; i<=clientes.size(); i++){
        	
        	Cliente actual = clientes.get(i);
        	System.out.println("Tiempor de " + i + ": " + actual.darTActualizacion() + ", " + actual.darTLlaveS());
        	HSSFRow rowheadN = sheet.createRow((short)i);
        	rowheadN.createCell(0).setCellValue(actual.darTActualizacion());
            rowheadN.createCell(1).setCellValue(actual.darTLlaveS());

        }
        try {
        	FileOutputStream fileOut = new FileOutputStream(filename);
			workbook.write(fileOut);
			fileOut.close();
			workbook.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void fail()
	{
		System.err.println(Task.MENSAJE_FAIL);
	}
	
	public void success()
	{
		System.err.println(Task.OK_MESSAGE);
	}
	
}
