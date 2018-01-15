<?php

/**
 * @copyright Copyright (c) 2017 Carlos Ramos
 * @package ktaris-csd
 * @version 0.1.0
 */

namespace ktaris\csd;

use ktaris\csd\CsdException;

trait Cer
{
    /**
     * @var string Recibe la trayectoria completa donde se encuentra
     * almacenado el archivo *.cer del CSD a ser leído.
     */
    public $archivo_cer;
    /**
     * @var string Determina el nombre del archivo que contiene el
     * contenido del certificado descifrado.
     * Se debe asegurar que se tengan permisos de escritura para
     * generar o regenerar el archivo *.cer.pem.
     */
    public $archivo_cer_pem;

    /**
     * @var string mantiene el contenido del archivo *.cer.pem en
     * memoria, generado a partir de [[archivo_cer]].
     */
    protected $_contenido_cer_pem;
    /**
     * @var array contiene todos los datos asociados al certificado
     * en un arreglo.
     */
    protected $_propiedades;

    /**
     * Lee el archivo .cer, genera un .pem en memoria, y lee las
     * propiedades del certificado.
     *
     * @return string contenido del archivo *.cer.pem.
     */
    public function leerCer()
    {
        $pem = $this->leerCerPem();
        $this->leerPropiedades();

        return $pem;
    }

    /**
     * Obtiene el contenido que va a un archivo .cer.pem, sin almacenar
     * el resultado en un archivo.
     * Basado en https://gist.github.com/ajzele/4585931
     *
     * @return string contenido del archivo *.cer.pem.
     */
    public function leerCerPem()
    {
        $nombreArchivoCer = $this->leerCertificado();

        $contenidoCerPem = '-----BEGIN CERTIFICATE-----'.PHP_EOL
                .chunk_split(base64_encode($nombreArchivoCer), 64, PHP_EOL)
            .'-----END CERTIFICATE-----'.PHP_EOL;

        $this->_contenido_cer_pem = $contenidoCerPem;

        return $contenidoCerPem;
    }

    /**
     * Se encarga de leer las propiedades a partir del contenido del *.pem.
     *
     * @return array arreglo de propiedades del certitifcado.
     */
    public function leerPropiedades()
    {
        $this->existeContenidoCerPem();

        $this->_propiedades = openssl_x509_parse($this->_contenido_cer_pem);

        return $this->_propiedades;
    }

    public function leerPropiedad($nombreDePropiedad)
    {
        if (!array_key_exists($nombreDePropiedad, $this->_propiedades)) {
            return null;
        }

        return $this->_propiedades[$nombreDePropiedad];
    }

    /**
     * Genera el archivo *.cer.pem en base al archivo definido en
     * [[archivo_cer]], para ser almacenado en [[archivo_cer_pem]],
     * si está definida, o en el mismo directorio que [[archivo_cer]],
     * agregando la extensión *.cer.pem.
     *
     * @param boolean $regenerar determina si se debe regenerar el archivo
     * *.cer.pem si esté ya se encuentra almacenado.
     *
     * @return string Contenido del archivo *.cer.pem generado.
     */
    public function generarArchivoCerPem($regenerar = false)
    {
        $nombrePem = $this->generarNombreDeArchivoCerPem();
        //Si el archivo no existe, o existe pero queremos sobreescribir, lo generamos.
        if (!file_exists($nombrePem) || (file_exists($nombrePem) && $regenerar)) {
            $contenidoCerPem = $this->leerCerPem();

            file_put_contents($nombrePem, $contenidoCerPem);
        }
        $archivoPem = file_get_contents($nombrePem);
        $this->archivo_cer_pem = $archivoPem;

        return $archivoPem;
    }

    // ==================================================================
    //
    // Funciones públicas para la obtención de atributos.
    //
    // ------------------------------------------------------------------

    /**
     * Regresa el atributo del certificado.
     *
     * @return string certificado
     */
    public function getCertificado()
    {
        $this->existeContenidoCerPem();

        $certificado = str_replace('-----BEGIN CERTIFICATE-----', '', $this->_contenido_cer_pem);
        $certificado = str_replace('-----END CERTIFICATE-----', '', $certificado);
        $certificado = preg_replace('/\s+/', '', trim($certificado));

        return $certificado;
    }

    /**
     * Se encarga de obtener el valor del atributo "NoCertificado" en
     *  base al contenido del *.pem.
     *
     * @return string valor del atributo NoCertificado.
     */
    public function getNoCertificado()
    {
        $this->existenPropiedades();

        $attr = $this->coronaConvierte($this->_propiedades['serialNumber']);

        return $attr;
    }

    public function getValidoDesde()
    {
        $timestamp = $this->getValidoDesdeTimestamp();

        return date('Y/m/d H:i:s', $timestamp);
    }

    public function getValidoHasta()
    {
        $timestamp = $this->getValidoHastaTimestamp();

        return date('Y/m/d H:i:s', $timestamp);
    }

    public function getValidoDesdeTimestamp()
    {
        return $this->_propiedades['validFrom_time_t'] + 0;
    }

    public function getValidoHastaTimestamp()
    {
        return $this->_propiedades['validTo_time_t'] + 0;
    }

    // ==================================================================
    //
    // Funciones internas para lectura y escritura de archivos.
    //
    // ------------------------------------------------------------------

    /**
     * Determina el nombre del archivo a ser generado, en base al
     * nombre en [[archivo_cer_pem]] o, si no está presente, en base
     * al nombre del archivo [[archivo_cer]], agregando *.pem.
     *
     * @return string nombre del archivo a ser generado.
     */
    protected function generarNombreDeArchivoCerPem()
    {
        $nombrePem = '';
        if (!empty($this->archivo_cer_pem)) {
            $nombrePem = $this->archivo_cer_pem;
        } else {
            $nombrePem = str_replace('.cer', '.cer.pem', $this->archivo);
        }

        return $nombrePem;
    }

    /**
     * Se encarga de leer el archivo del certificado provisto en
     * [[archivo_cer]], o arrojar una excepción si dicha propiedad no
     * fue configurada.
     *
     * @return string cadena con el contenido del archivo.
     */
    protected function leerCertificado()
    {
        if (empty($this->archivo_cer)) {
            throw new CsdException('No se especificó un archivo a ser leído.');
        }

        return file_get_contents($this->archivo_cer);
    }


    /**
     * Se encarga de generar una excepción si no contamos con el
     * contenido del archivo .cer.pem en memoria.
     *
     * @throws Exception si no se cuenta con el contenido del
     * archivo *.pem.
     */
    protected function existeContenidoCerPem()
    {
        if (empty($this->_contenido_cer_pem)) {
            throw new CsdException('No se cuenta con el contenido del archivo *.pem');
        }
    }

    /**
     * Se encarga de generar una excepción si no hemos cargado las
     * propiedades del *.pem en memoria.
     *
     * @throws Exception si no se cuenta con el contenido de la
     * variable [[_propiedades]].
     */
    protected function existenPropiedades()
    {
        if (empty($this->_propiedades)) {
            throw new CsdException('No han sido leídas las propiedades del archivo *.pem');
        }
    }

    // ==================================================================
    //
    // Funciones auxiliares proporcionadas por "La Corona".
    //
    // Su repositorio está en https://github.com/fortiz/sat
    //
    // ------------------------------------------------------------------

    protected function coronaConvierte($dec)
    {
        $hex = $this->coronaBcdechex($dec);
        $ser = "";
        for ($i = 1; $i < strlen($hex); $i = $i + 2) {
            $ser .= substr($hex, $i, 1);
        }
        return $ser;
    }

    protected function coronaBcdechex($dec)
    {
        $last = bcmod($dec, 16);
        $remain = bcdiv(bcsub($dec, $last), 16);
        if ($remain == 0) {
            return dechex($last);
        } else {
            return $this->coronaBcdechex($remain).dechex($last);
        }
    }
}
