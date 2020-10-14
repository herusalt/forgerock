<?php
/**
 * Samuelerwardi samuelerwardi@gmail.com
 */

namespace App\Forgerock;


use App\Forgerock\Exceptions\AuthPimcoreException;

final class MemberPimcore
{
    private static $instance = null;

    /**
     * Private ctor so nobody else can instantiate it
     *
     */
    private function __construct()
    {
    }

    /**
     * Call this method to get singleton
     * @param $memberForgeRockID
     * @return \Pimcore\Model\DataObject|null
     */
    public static function Instance($memberForgeRockID)
    {
        if (self::$instance === null) {
            $member = new  \App\Forgerock\Repositories\MembersRepository(new \Illuminate\Container\Container());
            $result = $member->findBy("forgeRockId", $memberForgeRockID);
            if (count($result) == 1) {
                self::$instance = $result[0];
            } else {
                throw new AuthPimcoreException(["token" => ["Member not found on apps"]]);
            }
        }
        return self::$instance;
    }
}


