<?php
/**
 * @copyright Copyright (c) 2017 Carlos Ramos
 * @package ktaris-csd
 * @version 0.1.0
 */

namespace ktaris\csd;

/**
 * Excepción que representa un error en la lectura del CSD.
 *
 * @author Carlos Ramos <carlos@ramoscarlos.com>
 */
class CsdException extends \Exception
{
    /**
     * @return string nombre bonito de la excepción
     */
    public function getName()
    {
        return 'Error en CSD';
    }
}
