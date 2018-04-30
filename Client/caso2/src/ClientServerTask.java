import java.io.IOException;
import java.net.UnknownHostException;

import uniandes.gload.core.Task;

public class ClientServerTask extends Task
{
	private Generator gen;
	
	public ClientServerTask (Generator generator)
	{
		gen = generator;
	}
	
	@Override
	public void execute()
	{
		try 
		{
			Cliente cliente = new Cliente();
			success();
		} 
		catch (Exception e) 
		{
			gen.aumentarPerdidas();
			fail();
		} 
	}

	@Override
	public void fail()
	{
		System.err.println(Task.MENSAJE_FAIL);
	}
	
	@Override
	public void success()
	{
		System.err.println(Task.OK_MESSAGE);
	}
	
}
