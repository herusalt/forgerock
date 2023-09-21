<?php
/**
 * Samuelerwardi samuelerwardi@gmail.com
 */

namespace App\Http\Middleware;

use Closure;
use Lcobucci\JWT\Parser;
use Illuminate\Http\Response;
use App\Forgerock\MemberPimcore;
use Lcobucci\JWT\UnencryptedToken;
use App\Forgerock\Traits\LoggingTrait;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;

class MemberPimcoreMiddleware
{
    use LoggingTrait;

    /**
     * Run the request filter.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @param string
     * @return mixed
     * @throws \Auth0\SDK\Exception\CoreException
     */
    public function handle($request, Closure $next)
    {
        $responseCode = 401;

        /** TOKEN REQUIRED */
        if ($request->hasHeader('Authorization')) {
            $authorization = $request->header('Authorization');
            $token = null;
            $authorizationHeader = str_replace('bearer ', '', $authorization);
            $token = str_replace('Bearer ', '', $authorizationHeader);

            $parser = new Parser();

            try {
                $parseData = $parser->parse($token);
            } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $e) {
                return response()->json([
                    'status' => false,
                    'code' => "AUTH401",
                    'message' => null,
                    'errorMessage' => "invalid processing token",
                    'data' => null
                ], $responseCode);
            }
           

            $memberForgeRockID = $parseData->claims()->get('sub');
            $memberPimcore = MemberPimcore::Instance($memberForgeRockID);
            $request->request->add(['memberPimcore' => $memberPimcore]);
            return $next($request);
        } else {
            return response()->json([
                'status' => false,
                'code' => "AUTH401",
                'message' => null,
                'errorMessage' => "token not validate",
                'data' => null
            ], $responseCode);
        }
    }

}
