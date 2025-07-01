declare module 'whois-json' {
  interface WhoisData {
    [key: string]: unknown;
    expirationDate?: string;
    registryExpiryDate?: string;
    'Registry Expiry Date'?: string;
    'Expiry date'?: string;
    creationDate?: string;
    registrationDate?: string;
    'Creation Date'?: string;
    'Registration Date'?: string;
    registrar?: string;
    'Registrar'?: string;
    'Registrar:'?: string;
  }

  function whois(domain: string): Promise<WhoisData>;
  export default whois;
} 