package eu.europa.esig.dss.web.config;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.sql.SQLException;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.sql.DataSource;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.io.ClassPathResource;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.SSLCertificateLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.server.signing.common.RemoteSignatureTokenConnection;
import eu.europa.esig.dss.ws.server.signing.common.RemoteSignatureTokenConnectionImpl;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.common.RemoteMultipleDocumentsSignatureServiceImpl;
import eu.europa.esig.dss.ws.timestamp.remote.RemoteTimestampService;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Configuration
@ComponentScan(basePackages = { "eu.europa.esig.dss.web.job", "eu.europa.esig.dss.web.service" })
@Import({ PropertiesConfig.class, CXFConfig.class, PersistenceConfig.class, ProxyConfiguration.class, WebSecurityConfig.class,
		SchedulingConfig.class })
@ImportResource({ "${tsp-source}" })
public class DSSBeanConfig {

	private static final Logger LOG = LoggerFactory.getLogger(DSSBeanConfig.class);

	@Value("${default.validation.policy}")
	private String defaultValidationPolicy;

	@Value("${current.lotl.url}")
	private String lotlUrl;

	@Value("${lotl.country.code}")
	private String lotlCountryCode;

	@Value("${current.oj.url}")
	private String currentOjUrl;

	@Value("${oj.content.keystore.type}")
	private String ksType;

	@Value("${oj.content.keystore.filename}")
	private String ksFilename;

	@Value("${oj.content.keystore.password}")
	private String ksPassword;

	@Value("${dss.server.signing.keystore.type}")
	private String serverSigningKeystoreType;

	@Value("${dss.server.signing.keystore.filename}")
	private String serverSigningKeystoreFilename;

	@Value("${dss.server.signing.keystore.password}")
	private String serverSigningKeystorePassword;

	@Autowired
	private TSPSource tspSource;

	@Autowired
	private DataSource dataSource;

	// can be null
	@Autowired(required = false)
	private ProxyConfig proxyConfig;
	
	@PostConstruct
	public void cachedCRLSourceInitialization() throws SQLException {
		JdbcCacheCRLSource jdbcCacheCRLSource = cachedCRLSource();
		jdbcCacheCRLSource.initTable();
	}
	
	@PostConstruct
	public void cachedOCSPSourceInitialization() throws SQLException {
		JdbcCacheOCSPSource jdbcCacheOCSPSource = cachedOCSPSource();
		jdbcCacheOCSPSource.initTable();
	}
	
	@PreDestroy
	public void cachedCRLSourceClean() throws SQLException {
		JdbcCacheCRLSource jdbcCacheCRLSource = cachedCRLSource();
		jdbcCacheCRLSource.destroyTable();
	}
	
	@PreDestroy
	public void cachedOCSPSourceClean() throws SQLException {
		JdbcCacheOCSPSource jdbcCacheOCSPSource = cachedOCSPSource();
		jdbcCacheOCSPSource.destroyTable();
	}

	@Bean
	public CommonsDataLoader dataLoader() {
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setProxyConfig(proxyConfig);
		return dataLoader;
	}
	
	@Bean
    public CommonsDataLoader trustAllDataLoader() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setProxyConfig(proxyConfig);
		dataLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);
        return dataLoader;
    }

	@Bean
	public OCSPDataLoader ocspDataLoader() {
		OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
		ocspDataLoader.setProxyConfig(proxyConfig);
		return ocspDataLoader;
	}

	@Bean
	public FileCacheDataLoader fileCacheDataLoader() {
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
		fileCacheDataLoader.setDataLoader(dataLoader());
		// Per default uses "java.io.tmpdir" property
		// fileCacheDataLoader.setFileCacheDirectory(new File("/tmp"));
		return fileCacheDataLoader;
	}

	@Bean
	public OnlineCRLSource onlineCRLSource() {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(dataLoader());
		return onlineCRLSource;
	}

	@Bean
	public JdbcCacheCRLSource cachedCRLSource() {
		JdbcCacheCRLSource jdbcCacheCRLSource = new JdbcCacheCRLSource();
		jdbcCacheCRLSource.setDataSource(dataSource);
		jdbcCacheCRLSource.setProxySource(onlineCRLSource());
		jdbcCacheCRLSource.setDefaultNextUpdateDelay((long) (60 * 3)); // 3 minutes
		return jdbcCacheCRLSource;
	}

	@Bean
	public OnlineOCSPSource onlineOcspSource() {
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		onlineOCSPSource.setDataLoader(ocspDataLoader());
		return onlineOCSPSource;
	}

	@Bean
	public JdbcCacheOCSPSource cachedOCSPSource() {
		JdbcCacheOCSPSource jdbcCacheOCSPSource = new JdbcCacheOCSPSource();
		jdbcCacheOCSPSource.setDataSource(dataSource);
		jdbcCacheOCSPSource.setProxySource(onlineOcspSource());
		jdbcCacheOCSPSource.setDefaultNextUpdateDelay((long) (1000 * 60 * 3)); // 3 minutes
		return jdbcCacheOCSPSource;
	}

	@Bean(name = "european-trusted-list-certificate-source")
	public TrustedListsCertificateSource trustedListSource() {
		return new TrustedListsCertificateSource();
	}

	@Bean
	public CertificateVerifier certificateVerifier() throws Exception {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(cachedCRLSource());
		certificateVerifier.setOcspSource(cachedOCSPSource());
		certificateVerifier.setDataLoader(dataLoader());
		certificateVerifier.setTrustedCertSources(trustedListSource());


		// dstu certs
		CommonTrustedCertificateSource cs = new CommonTrustedCertificateSource();
		cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFZTCCBOGgAwIBAgIUPbc+e/DVdbIBAAAAAQAAAIEAAAAwDQYLKoYkAgEBAQEDAQEwgfoxPzA9BgNVBAoMNtCc0ZbQvdGW0YHRgtC10YDRgdGC0LLQviDRjtGB0YLQuNGG0ZbRlyDQo9C60YDQsNGX0L3QuDExMC8GA1UECwwo0JDQtNC80ZbQvdGW0YHRgtGA0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA0KbQtdC90YLRgNCw0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz0LDQvTEZMBcGA1UEBQwQVUEtMDAwMTU2MjItMjAxNzELMAkGA1UEBhMCVUExETAPBgNVBAcMCNCa0LjRl9CyMB4XDTE3MDkyMjA3MTkwMFoXDTI3MDkyMjA3MTkwMFowgfoxPzA9BgNVBAoMNtCc0ZbQvdGW0YHRgtC10YDRgdGC0LLQviDRjtGB0YLQuNGG0ZbRlyDQo9C60YDQsNGX0L3QuDExMC8GA1UECwwo0JDQtNC80ZbQvdGW0YHRgtGA0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA0KbQtdC90YLRgNCw0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz0LDQvTEZMBcGA1UEBQwQVUEtMDAwMTU2MjItMjAxNzELMAkGA1UEBhMCVUExETAPBgNVBAcMCNCa0LjRl9CyMIIBUTCCARIGCyqGJAIBAQEBAwEBMIIBATCBvDAPAgIBrzAJAgEBAgEDAgEFAgEBBDbzykDGaaTaFzFJyhLDLa4Ya1Osa8Y2WZferq6K0tiI+b/VNAFpTvnEJz2M/m3Cj3BqD0kQzgMCNj///////////////////////////////////7oxdUWACajApyTwL4Gqih/Lr4DZDHqVEQUEzwQ2fIV8lMVDO/2ZHhfCJoQGWFCpoknte8JJrlpOh4aJ+HLvetUkCC7DA46a7ee6a6Ezgdl5umIaBECp1utF8TxwgoDElnsjH16t9ljrpMA3KR042WvwJcpOF/jpcg3GFbQ6KJdfC8Heo2Q4tWTqLBef0BI+bbj6xXkEAzkABDYb4w66IKfDEdOz7rn4zYcIy8/GXTJJVLpKPm/sjnb255xZPsT7pzixk608EPRZzbQulpa+fhOjggFEMIIBQDApBgNVHQ4EIgQgvbc+e/DVdbJIAng9ngWpUJd2wXX3rIF2dAgHlno0IBQwKwYDVR0jBCQwIoAgvbc+e/DVdbJIAng9ngWpUJd2wXX3rIF2dAgHlno0IBQwDgYDVR0PAQH/BAQDAgEGMBkGA1UdIAEB/wQPMA0wCwYJKoYkAgEBAQICMBIGA1UdEwEB/wQIMAYBAf8CAQIwHgYIKwYBBQUHAQMBAf8EDzANMAsGCSqGJAIBAQECATBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3pvLmdvdi51YS9kb3dubG9hZC9jcmxzL0NaTy0yMDE3LUZ1bGwuY3JsMEMGA1UdLgQ8MDowOKA2oDSGMmh0dHA6Ly9jem8uZ292LnVhL2Rvd25sb2FkL2NybHMvQ1pPLTIwMTctRGVsdGEuY3JsMA0GCyqGJAIBAQEBAwEBA28ABGyM+R9vCn1p+BoSw0fYUfnSiIGNAuro/T7ujYr/i4go9DU/7EJrVfCnPQwHTeHTTxPZnllXPRESmRr+4SjSUJ/Fs9jBqpDuH+tmUUNsB+TT7YfUPs6evaP52j9ud+gFQmS5COCTKdOTcEeAViI="));
		cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFWzCCBNegAwIBAgIUPbc+e/DVdbICAAAAAQAAAIIAAAAwDQYLKoYkAgEBAQEDAQEwgfoxPzA9BgNVBAoMNtCc0ZbQvdGW0YHRgtC10YDRgdGC0LLQviDRjtGB0YLQuNGG0ZbRlyDQo9C60YDQsNGX0L3QuDExMC8GA1UECwwo0JDQtNC80ZbQvdGW0YHRgtGA0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA0KbQtdC90YLRgNCw0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz0LDQvTEZMBcGA1UEBQwQVUEtMDAwMTU2MjItMjAxNzELMAkGA1UEBhMCVUExETAPBgNVBAcMCNCa0LjRl9CyMB4XDTE3MDkyMjA3NDUwMFoXDTIyMDkyMjA3NDUwMFowggEMMT8wPQYDVQQKDDbQnNGW0L3RltGB0YLQtdGA0YHRgtCy0L4g0Y7RgdGC0LjRhtGW0Zcg0KPQutGA0LDRl9C90LgxMTAvBgNVBAsMKNCQ0LTQvNGW0L3RltGB0YLRgNCw0YLQvtGAINCG0KLQoSDQptCX0J4xWzBZBgNVBAMMUk9DU1At0YHQtdGA0LLQtdGAINCm0LXQvdGC0YDQsNC70YzQvdC40Lkg0LfQsNGB0LLRltC00YfRg9Cy0LDQu9GM0L3QuNC5INC+0YDQs9Cw0L0xGTAXBgNVBAUMEFVBLTAwMDE1NjIyLTIwMTcxCzAJBgNVBAYTAlVBMREwDwYDVQQHDAjQmtC40ZfQsjCB8jCByQYLKoYkAgEBAQEDAQEwgbkwdTAHAgIBAQIBDAIBAAQhEL7j22rqnh+GV4xFwSWU/5QjlKfXOPkYfmUVAXKU9M4BAiEAgAAAAAAAAAAAAAAAAAAAAGdZITrxgumH0+F3FJB9Rw0EIbYP0tjc6Kk0I8YQG8qRxHoAfmwwCybNVWybDn0g7ykqAARAqdbrRfE8cIKAxJZ7Ix9erfZY66TANykdONlr8CXKThf46XINxhW0OiiXXwvB3qNkOLVk6iwXn9ASPm24+sV5BAMkAAQhZhGS3bE+ULMsxMxFK0mhqR8QjJDzd9vPSGP/te66Y5QAo4IBhzCCAYMwKQYDVR0OBCIEIPo4wVHxDcSCnuOn3wuW6LqDXLHkG5fZcvEhx4+nkXznMCsGA1UdIwQkMCKAIL23Pnvw1XWySAJ4PZ4FqVCXdsF196yBdnQIB5Z6NCAUMC8GA1UdEAQoMCagERgPMjAxNzA5MjIwNzQ1MDBaoREYDzIwMjIwOTIyMDc0NTAwWjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwGQYDVR0gAQH/BA8wDTALBgkqhiQCAQEBAgIwDAYDVR0TAQH/BAIwADAeBggrBgEFBQcBAwEB/wQPMA0wCwYJKoYkAgEBAQIBMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jem8uZ292LnVhL2Rvd25sb2FkL2NybHMvQ1pPLTIwMTctRnVsbC5jcmwwQwYDVR0uBDwwOjA4oDagNIYyaHR0cDovL2N6by5nb3YudWEvZG93bmxvYWQvY3Jscy9DWk8tMjAxNy1EZWx0YS5jcmwwDQYLKoYkAgEBAQEDAQEDbwAEbF5XwyQoGZgkqIo3i/jMfQSpXc+e+9uGZ12Sh063r2rfOy2BYDxpIJ39c8Lil/PkA3zfDtHRE2PpolDrO3CMTJrjdtqLaaZr9xJCpzfrr9pBr/YZOKPZU4ycPOcWUCt3eZY+W1uORRXsp1vcJA=="));
		//cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(""));
		//cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(""));
		cs.importAsTrusted(trustedListSource());

		certificateVerifier.addTrustedCertSources(cs);



		// Default configs
		certificateVerifier.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
		certificateVerifier.setCheckRevocationForUntrustedChains(true);

		return certificateVerifier;
	}

	@Bean
	public ClassPathResource defaultPolicy() {
		return new ClassPathResource(defaultValidationPolicy);
	}

	@Bean
	public CAdESService cadesService() throws Exception {
		CAdESService service = new CAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public XAdESService xadesService() throws Exception {
		XAdESService service = new XAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public PAdESService padesService() throws Exception {
		PAdESService service = new PAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public ASiCWithCAdESService asicWithCadesService() throws Exception {
		ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public ASiCWithXAdESService asicWithXadesService() throws Exception {
		ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public RemoteDocumentSignatureServiceImpl remoteSignatureService() throws Exception {
		RemoteDocumentSignatureServiceImpl service = new RemoteDocumentSignatureServiceImpl();
		service.setAsicWithCAdESService(asicWithCadesService());
		service.setAsicWithXAdESService(asicWithXadesService());
		service.setCadesService(cadesService());
		service.setXadesService(xadesService());
		service.setPadesService(padesService());
		return service;
	}

	@Bean
	public RemoteMultipleDocumentsSignatureServiceImpl remoteMultipleDocumentsSignatureService() throws Exception {
		RemoteMultipleDocumentsSignatureServiceImpl service = new RemoteMultipleDocumentsSignatureServiceImpl();
		service.setAsicWithCAdESService(asicWithCadesService());
		service.setAsicWithXAdESService(asicWithXadesService());
		service.setXadesService(xadesService());
		return service;
	}

	@Bean
	public RemoteDocumentValidationService remoteValidationService() throws Exception {
		RemoteDocumentValidationService service = new RemoteDocumentValidationService();
		service.setVerifier(certificateVerifier());
		return service;
	}
	
	@Bean
	public RemoteCertificateValidationService RemoteCertificateValidationService() throws Exception {
		RemoteCertificateValidationService service = new RemoteCertificateValidationService();
		service.setVerifier(certificateVerifier());
		return service;
	}

	@Bean
	public KeyStoreSignatureTokenConnection remoteToken() throws IOException {
		return new KeyStoreSignatureTokenConnection(new ClassPathResource(serverSigningKeystoreFilename).getFile(), serverSigningKeystoreType,
				new PasswordProtection(serverSigningKeystorePassword.toCharArray()));
	}

	@Bean
	public RemoteSignatureTokenConnection serverToken() throws IOException {
		RemoteSignatureTokenConnectionImpl remoteSignatureTokenConnectionImpl = new RemoteSignatureTokenConnectionImpl();
		remoteSignatureTokenConnectionImpl.setToken(remoteToken());
		return remoteSignatureTokenConnectionImpl;
	}
	
	@Bean
	public RemoteTimestampService timestampService() throws IOException {
		RemoteTimestampService timestampService = new RemoteTimestampService();
		timestampService.setTSPSource(tspSource);
		return timestampService;
	}

	@Bean
	public KeyStoreCertificateSource ojContentKeyStore() {
		try {
			return new KeyStoreCertificateSource(new ClassPathResource(ksFilename).getFile(), ksType, ksPassword);
		} catch (IOException e) {
			throw new DSSException("Unable to load the file " + ksFilename, e);
		}
	}
	
	@Bean 
	public TLValidationJob job() {
		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(trustedListSource());
		job.setListOfTrustedListSources(europeanLOTL());
		job.setOfflineDataLoader(offlineLoader());
		job.setOnlineDataLoader(onlineLoader());

		// ukranian  TLS
		TLSource uaTLS = new TLSource();
		uaTLS.setUrl("https://czo.gov.ua/download/tl/TL-UA.xml");
		CommonTrustedCertificateSource uaCert = new CommonTrustedCertificateSource();
		uaCert.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		uaCert.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		uaCert.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));


		uaTLS.setCertificateSource(uaCert);
		job.setTrustedListSources(uaTLS);

		return job;
	}

	@Bean
	public DSSFileLoader onlineLoader() {
		FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
		onlineFileLoader.setCacheExpirationTime(0);
		onlineFileLoader.setDataLoader(dataLoader());
		onlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return onlineFileLoader;
	}

	@Bean(name = "european-lotl-source")
	public LOTLSource europeanLOTL() {
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl(lotlUrl);
		lotlSource.setCertificateSource(ojContentKeyStore());
		lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(currentOjUrl));
		lotlSource.setPivotSupport(true);
		return lotlSource;
	}

	@Bean
	public DSSFileLoader offlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new IgnoreDataLoader());
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	@Bean
	public File tlCacheDirectory() {
		File rootFolder = new File(System.getProperty("java.io.tmpdir"));
		File tslCache = new File(rootFolder, "dss-tsl-loader");
		if (tslCache.mkdirs()) {
			LOG.info("TL Cache folder : {}", tslCache.getAbsolutePath());
		}
		return tslCache;
	}
	
    /* QWAC Validation */

    @Bean
    public SSLCertificateLoader sslCertificateLoader() {
        SSLCertificateLoader sslCertificateLoader = new SSLCertificateLoader();
        sslCertificateLoader.setCommonsDataLoader(trustAllDataLoader());
        return sslCertificateLoader;
    }

}