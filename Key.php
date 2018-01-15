<?php

/**
 * @copyright Copyright (c) 2017 Carlos Ramos
 * @package ktaris-csd
 * @version 0.0.1
 */

namespace ktaris\csd;

use ktaris\csd\CsdException;

trait Key
{
    /**
     * @var string Recibe la trayectoria completa donde se encuentra
     * almacenado el archivo *.key del CSD a ser leído.
     */
    public $archivo_key;
    /**
     * @var string Determina el nombre del archivo que contiene el
     * contenido del certificado descifrado.
     * Se debe asegurar que se tengan permisos de escritura para
     * generar o regenerar el archivo *.key.pem.
     */
    public $archivo_key_pem;
    /**
     * @var string La contraseña que descifra la llave privada.
     */
    public $llave;

    /**
     * @var string mantiene el contenido del archivo *.key.pem en
     * memoria, generado a partir de [[archivo_key]].
     */
    protected $_contenido_key_pem;

    // ==================================================================
    //
    // Funciones públicas
    //
    // ------------------------------------------------------------------

    /**
     * Función utilizada para sellar una cadena con SHA-1.
     *
     * El caso de uso que me ha tocado es para generar un XML de cancelación con el
     * proveedor RealVirtual, motivo por el que se usa el sellado con este algoritmo.
     *
     * @param string $cadena cadena que será sellada.
     *
     * @return string sello de la cadena
     */
    public function generarSelloConSha1($cadena)
    {
        return $this->generarSello($cadena, OPENSSL_ALGO_SHA1);
    }

    /**
     * Función utilizada para la generación del sello del pre-cfdi.
     * Según el anexo 20, en la sección de "Generación del Sello Digital",
     * por la página 56, el sello se genera en los siguientes pasos:
     *     1. Obtener la cadena original del CFD.
     *     2. Aplicar el algoritmo SHA1 a la cadena original (aunque aplicamo SHA256).
     *     3. Cifrar con RSA.
     *     4. Convertir a base64.
     * Otra referencia es: http://solucionfactible.com/sfic/capitulos/timbrado/sello.jsp.
     *
     * @param string $cadena cadena que será sellada.
     *
     * @return string sello de la cadena
     */
    public function generarSelloConSha256($cadena)
    {
        return $this->generarSello($cadena, OPENSSL_ALGO_SHA256);
    }

    /**
     * Se encarga de generar el archivo *.key.pem a partir del archivo
     * *.key y la llave privada.
     * Referencias:
     *     http://actron.wordpress.com/tag/php-sello-digital/
     *     http://www.forosdelweb.com/f18/facturacion-electronica-mexico-638882/
     *
     * @param boolean $regenerar determina si se debe regenerar el archivo
     * *.pem si esté ya se encuentra almacenado.
     *
     * @return string contenido del archivo *.key.pem.
     */
    public function generarArchivoKeyPem($regenerar = false)
    {
        $nombrePem = $this->generarNombreDeArchivoKeyPem();
        if (!file_exists($nombrePem) || (file_exists($nombrePem) && $regenerar)) {
            system("openssl pkcs8 -inform DER -in {$this->archivo_key} -passin pass:{$this->llave} -out $nombrePem");
        }
        $contenidoPem = file_get_contents($nombrePem);
        if (empty($contenidoPem)) {
            throw new CsdException('La llave privada del certificado es incorrecta.');
        }
        $this->_contenido_key_pem = $contenidoPem;

        return $contenidoPem;
    }

    // ==================================================================
    //
    // Funciones internas para lectura y escritura de archivos.
    //
    // ------------------------------------------------------------------

    /**
     * Función interna que genera el sello para la [cadena] en base al algoritmo definido
     * por [tipo_de_sha], ya sea SHA1 o SHA256.
     *
     * @param  string  $cadena      cadena a sellar
     * @param  integer $tipo_de_sha tipo de SHA a usar, ya sea SHA1 o SHA256
     *
     * @return string  sello generado
     */
    protected function generarSello($cadena, $tipo_de_sha)
    {
        $private_key = openssl_pkey_get_private($this->_contenido_key_pem);
        openssl_sign($cadena, $selloBinario, $private_key, $tipo_de_sha);
        openssl_pkey_free($private_key);
        $sello = base64_encode($selloBinario);

        return $sello;
    }

    /**
     * Determina el nombre del archivo a ser generado, en base al
     * nombre en [[archivo_key_pem]] o, si no está presente, en base
     * al nombre del archivo [[archivo_key]], agregando *.pem.
     *
     * @return string nombre del archivo key a ser generado.
     */
    protected function generarNombreDeArchivoKeyPem()
    {
        $nombrePem = '';
        if (!empty($this->archivo_key_pem)) {
            $nombrePem = $this->archivo_key_pem;
        } else {
            $nombrePem = str_replace('.key', '.key.pem', $this->archivo_key);
        }

        return $nombrePem;
    }
}
