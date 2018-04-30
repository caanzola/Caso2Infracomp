import java.io.IOException;
import java.net.UnknownHostException;

import uniandes.gload.core.Task;

public class ClientServerTask extends Task
{
	
	@Override
	public void execute()
	{
		try {
			Cliente cliente = new Cliente();
			success();
		} catch (Exception e) {

			fail();
		} 
	}

	@Override
	public void fail()
	{
		System.out.println(Task.MENSAJE_FAIL);
	}
	
	@Override
	public void success()
	{
		System.out.println(Task.OK_MESSAGE);
	}
	
}
