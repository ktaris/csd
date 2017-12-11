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
