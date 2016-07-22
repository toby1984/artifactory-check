/**
 * Copyright 2004-2011 Tobias Gierke <tobias.gierke@code-sourcery.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.artifactory;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;

import org.w3c.dom.*;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Tiny multi-threaded program that scans a directory tree containing a system
 * export from Artifactory for .jar files and validates their MD5/SHA1 checksums against
 * the checksum given in the &lt;ARTIFACT&gt;jar.artifactory-metadata/artifactory-file.xml.
 * 
 * <p>
 * Command-line arguments:
 * 
 * <pre>
 * [-t <thread count>] [-v] &lt;directory name&gt;
 * </pre>
 * </p>
 * @author tobias.gierke@code-sourcery.de
 */
public class ArtifactoryCheck 
{
	private static final char[] NIBBLE_TO_CHAR = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	
	private boolean debug = false;
	private int threadCount=10;
	
	private final XPathExpression checksumExpression;

	private final BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(100);
	
	private ThreadPoolExecutor pool;
	
	private final AtomicInteger artifactsOk = new AtomicInteger(0);
	private final AtomicInteger artifactsCorrupted = new AtomicInteger(0);
	
	private static final ThreadLocal<byte[]> fileReadBuffer = new ThreadLocal<byte[]>() 
	{
		protected byte[] initialValue() 
		{
			return new byte[1024*1024];
		};
	};		
	
	private static final ThreadLocal<byte[]> expectedChecksum = new ThreadLocal<byte[]>() 
	{
		protected byte[] initialValue() {
			return new byte[1024];
		};
	};	
	
	private static final ThreadLocal<MessageDigest> md5Digest = new ThreadLocal<MessageDigest>() 
	{
		protected MessageDigest initialValue() 
		{
			try {
				return MessageDigest.getInstance("MD5");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		};
	};	
	
	private static final ThreadLocal<MessageDigest> sha1Digest = new ThreadLocal<MessageDigest>() 
	{
		protected MessageDigest initialValue() 
		{
			try {
				return MessageDigest.getInstance("SHA1");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		};
	};		
	
	public static void main(String[] args) throws IOException, ParserConfigurationException, SAXException, InterruptedException 
	{
		new ArtifactoryCheck().runWithCommandLineOptions(args);
	}
	
	public void runWithCommandLineOptions( String[] args) throws IOException, ParserConfigurationException, SAXException, InterruptedException 
	{
		final ArtifactoryCheck executable = new ArtifactoryCheck();
		
		final Runnable printHelp = () -> {
			System.out.println("Usage: [-t <thread count>] [-v] <directory>");
			System.exit(1);			
		};
		String file = null;
		for ( int i = 0 ; i < args.length ; i++ ) 
		{
			String arg = args[i].trim();
			if ( arg.startsWith("-" ) ) {
				arg = arg.toLowerCase();
				switch( arg ) {
					case "-help":
					case "--help":
						printHelp.run(); // calls System.exit()
						break;
					case "-t":
						executable.setThreadCount( Integer.parseInt( args[i+1 ] ));
						i++;
						continue;
					case "-v":
						executable.setDebug( true );
						continue;
					default:
						throw new RuntimeException("Unsupported argument: '"+arg+"'");
				}
			} 
			else 
			{
				if ( file != null ) {
					throw new RuntimeException("You cannot specify more than one folder on the command line");
				}
				file = arg;
			}
		}
		if ( file == null ) 
		{
			System.err.println("No directory specified on command line\n");
			printHelp.run(); // calls System.exit()
		}
		Path directory = Paths.get( file );
		if ( ! ( Files.exists( directory ) && Files.isDirectory( directory ) ) ) 
		{
			throw new IllegalArgumentException("Not a directory or does not exist: "+file);
		}		
		executable.run( directory );		
	}

	public ArtifactoryCheck() 
	{
		final XPathFactory factory = XPathFactory.newInstance();
		final XPath xpath = factory.newXPath();

		try {
			checksumExpression = xpath.compile("/artifactory-file/additionalInfo/checksumsInfo/checksums/checksum");
		} 
		catch (XPathExpressionException e) 
		{
			throw new RuntimeException(e);
		}		
	}
	
	private void setupThreadPool() 
	{
		if ( pool == null ) {
			System.out.println("Using "+threadCount+" threads.");
			pool = new ThreadPoolExecutor(threadCount, threadCount, 60, TimeUnit.SECONDS, workQueue,new ThreadPoolExecutor.CallerRunsPolicy());
		}
	}
	
	public void setThreadCount(int threadCount) 
	{
		if ( threadCount < 1 ) {
			throw new IllegalArgumentException("Thread count needs to be >= 1");
		}
		this.threadCount = threadCount;
	}
	
	public void run(Path file) throws IOException, ParserConfigurationException, SAXException, InterruptedException {
	
		setupThreadPool();
		
		scanSubtree( file );
		
		while ( ! workQueue.isEmpty() ) 
		{
			Thread.currentThread().sleep( 1000 );
		}
		
		pool.shutdown();
		
		System.out.flush();
		System.out.println("Finished, terminating.");		
		
		while ( ! pool.awaitTermination(1 , TimeUnit.SECONDS ) );
		
		System.out.flush();
		System.out.println("Artifacts OK       : "+artifactsOk.get());
		System.out.println("Artifacts CORRUPTED: "+artifactsCorrupted.get());		
		System.out.flush();
	}

	private void scanSubtree(Path file) throws IOException, ParserConfigurationException, SAXException, InterruptedException 
	{
		final DirectoryStream<Path> directoryStream = Files.newDirectoryStream(file);
		for (Path path : directoryStream) 
		{
			if (Files.isDirectory(path)) 
			{
				scanSubtree(path);
			} 
			else if (Files.isRegularFile(path) && path.toString().endsWith(".jar")) 
			{
				pool.submit( new Runnable() 
				{
					public void run() 
					{
						try {
							checkFile(path);
						} 
						catch (ParserConfigurationException | SAXException | IOException e) 
						{
							System.err.println("Thread "+Thread.currentThread().getName()+" failed: "+e.getMessage());
						}
					}
				} );
			}
		}
		directoryStream.close();
	}
	
	private void checkFile(Path path) throws ParserConfigurationException, SAXException, IOException 
	{
		final String p = path.toString() + ".artifactory-metadata/artifactory-file.xml";
		final Path xml = Paths.get(p);
		if ( Files.exists(xml) && Files.isRegularFile(xml) ) 
		{
			final byte[] expectedChecksum = ArtifactoryCheck.expectedChecksum.get();
			
			final Document doc = parseXML( xml );
			final NodeList list = evaluate( checksumExpression , doc );
			visit( list , checksum -> 
			{
				final int expectedChecksumLen = hexStringToByteArray( getNodeValue( checksum , "original" ) , expectedChecksum );
				if ( expectedChecksumLen < 5 ) {
					throw new RuntimeException("Hash value too small");
				}
				final String checksumType = getNodeValue( checksum , "type" );
				final byte[] actualChecksum;
				switch( checksumType ) 
				{
					case "md5":
						actualChecksum = digest( path , md5Digest.get() );
						break;
					case "sha1":
						actualChecksum = digest( path , sha1Digest.get() );
						break;
					default:
						throw new RuntimeException("Unhandled checksum type '"+checksumType+"'");
				}

				if ( debug ) {
					System.out.println( xml+" , "+checksumType+": \nexpected="+toString(expectedChecksum,expectedChecksumLen)+"\nactual  ="+toString(actualChecksum,actualChecksum.length) );
				}
				if ( actualChecksum.length != expectedChecksumLen ) {
					artifactsCorrupted.incrementAndGet();
					System.err.println("Artifact corrupted: "+path.toString()+" , ("+checksumType+"): expected = "+toString( expectedChecksum , expectedChecksumLen )+" <-> actual   = "+toString( actualChecksum , actualChecksum.length ) );
					return;
				}
				for ( int i = 0 ; i < expectedChecksumLen ; i++ ) 
				{
					if ( actualChecksum[i] != expectedChecksum[i] ) 
					{
						System.err.println("Artifact corrupted: "+path.toString()+" , ("+checksumType+"): expected = "+toString( expectedChecksum , expectedChecksumLen )+" <-> actual   = "+toString( actualChecksum , actualChecksum.length ) );
						artifactsCorrupted.incrementAndGet();
						return;
					}
				}
				artifactsOk.incrementAndGet();
				if ( debug && false ) {
					System.out.println("OK ("+checksumType+"): "+xml);
				}
			});
		} 
		else 
		{
			if (debug) {
				debug("No artifactory XML metadata for " + path);
			}
		}
	}
	
	private String toString(byte[] s,int len) 
	{
		final StringBuilder buffer = new StringBuilder();
		for ( int i = 0 ; i < len ; i++ ) 
		{
			final int value = s[i];
			buffer.append( NIBBLE_TO_CHAR[ (value & 0xf0) >>> 4 ] );
			buffer.append( NIBBLE_TO_CHAR[ (value & 0x0f)       ] );
		}
		return buffer.toString();
	}
	
	private byte[] digest(Path file, MessageDigest digest)
	{
		digest.reset();
		
		final byte[] buffer = fileReadBuffer.get();
		
		int len = 0;
		try ( InputStream in = Files.newInputStream( file ) ) 
		{
			while ( (len = in.read( buffer ) ) > 0 ) 
			{
				digest.update( buffer , 0 , len );
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return digest.digest();
	}
	
	private void visit(NodeList list,Consumer<Element> consumer) 
	{
		for ( int i = 0 , len = list.getLength() ; i < len ; i++ ) 
		{
			final Node item = list.item(i);
			if ( item instanceof Element) 
			{
				consumer.accept( (Element) item );
			}
		}
	}
	
	private int hexStringToByteArray(String s,byte[] buffer) 
	{
		if ( s == null || s.length() < 2 || !(s.length() % 2 == 0) ) {
			throw new RuntimeException("Not a valid hex string: "+s);
		}
		int bytesWritten = 0;
		for ( int i = 0 , len = s.length() ; i < len ; i+= 2) {
			final int hi = charToNibble( s.charAt(i ) );
			final int low = charToNibble( s.charAt(i+1 ) );
			buffer[bytesWritten++] = (byte) (hi<<4|low);
		}
		return bytesWritten;
	}
	
	private int charToNibble(char c) 
	{
		switch(c) {
			case '0': return 0x00;
			case '1': return 0x01;
			case '2': return 0x02;
			case '3': return 0x03;
			case '4': return 0x04;
			case '5': return 0x05;
			case '6': return 0x06;
			case '7': return 0x07;
			case '8': return 0x08;
			case '9': return 0x09;
			case 'a': return 0x0a;
			case 'b': return 0x0b;
			case 'c': return 0x0c;
			case 'd': return 0x0d;
			case 'e': return 0x0e;
			case 'f': return 0x0f;
			default:
				throw new IllegalArgumentException("Not a recognized hex-character: '"+c+"'");
		}
	}
	
	public interface IntVisitor 
	{
		public int accept(Element e);
	}

	private String getNodeValue(Element parent,String child) {
	
		final NodeList list = parent.getChildNodes();
		for ( int i = 0 , len = list.getLength() ; i < len ; i++ ) 
		{
			final Node item = list.item(i);
			if ( item instanceof Element) 
			{
				final Element e = (Element) item;
				if ( e.getTagName().equals( child ) ) 
				{
					return e.getTextContent();
				}
			}
		}		
		throw new RuntimeException("Parent "+parent+" has no child tag named '"+child+"'");
	}
	
    private NodeList evaluate(XPathExpression expr, Node document)
    {
        if ( expr == null ) {
            throw new IllegalArgumentException("expression must not be NULL.");
        }
        if ( document == null ) {
            throw new IllegalArgumentException("document must not be NULL.");
        }
        try {
            return (NodeList) expr.evaluate(document,XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        }
    }	

	private void debug(String msg) {
		System.out.println("DEBUG: " + msg);
	}

	protected static Document parseXML(Path file) throws ParserConfigurationException, SAXException, IOException {
		final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

		final DocumentBuilder builder = factory.newDocumentBuilder();

		// set fake EntityResolver , otherwise parsing is incredibly slow (~1 sec per file on my i7)
		// because the parser will download the DTD from the internet...
		builder.setEntityResolver(new DummyResolver());

		return builder.parse(Files.newInputStream(file));
	}

	private static final class DummyResolver implements EntityResolver {

		@Override
		public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
			final ByteArrayInputStream dummy = new ByteArrayInputStream(new byte[0]);
			return new InputSource(dummy);
		}
	}
	
	public void setDebug(boolean debug) {
		this.debug = debug;
	}
}