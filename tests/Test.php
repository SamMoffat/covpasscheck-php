<?php

namespace stwon\CovPassCheck\Tests;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagObjectManager;
use Mhauri\Base45;
use PHPUnit\Framework\TestCase;
use stwon\CovPassCheck\CoseSign1Tag;
use stwon\CovPassCheck\CovPassCheck;
use stwon\CovPassCheck\Exceptions\InvalidSignatureException;
use stwon\CovPassCheck\HealthCertificate\HealthCertificate;
use stwon\CovPassCheck\HealthCertificate\Target;
use stwon\CovPassCheck\Trust\TrustAnchor;
use stwon\CovPassCheck\Trust\TrustStore;

class Test extends TestCase
{
    public function testThisRuns()
    {
        $data = json_decode(file_get_contents('./_files/CO5.json'), true, 512, JSON_THROW_ON_ERROR);
        $base45Processor = new Base45();
        $payload = explode('HC1:', $data['PREFIX']);
        $decoded = $base45Processor->decode(end($payload));

        $decompressed = zlib_decode($decoded);
        $stream = new StringStream($decompressed);

        $tagObjectManager = new TagObjectManager();
        $tagObjectManager->add(CoseSign1Tag::class);
        $cborDecoder = new Decoder($tagObjectManager, new OtherObjectManager());

        $cbor = $cborDecoder->decode($stream);
        if (!$cbor instanceof CoseSign1Tag) {
            throw new \InvalidArgumentException('Not a valid certificate. Not a CoseSign1 type.');
        }

        $list = $cbor->getValue();

        if (!$list instanceof ListObject) {
            throw new \InvalidArgumentException('Not a valid certificate. No list.');
        }
        if (4 !== $list->count()) {
            throw new \InvalidArgumentException('Not a valid certificate. The list size is not correct.');
        }

        $firstItem = $list->get(0);
        $headerStream = new StringStream($firstItem->getValue());
        $protectedHeader = $cborDecoder->decode($headerStream);

        $secondItem = $list->get(1);
        $unprotectedHeader = $secondItem;
        $keyId = base64_encode(($unprotectedHeader->getNormalizedData() + $protectedHeader->getNormalizedData())[4]);

        $fourthItem = $list->get(3);
        if (!$fourthItem instanceof ByteStringObject) {
            throw new \InvalidArgumentException('Not a valid certificate. The signature is not a byte string.');
        }
        $signature = $fourthItem;

        $testTrustStoreData = [
            'certificates' => [
                [
                    'certificateType' => 'DSC',
                    'country'         => 'AT',
                    'kid'             => $keyId,
                    'rawData'         => $data['TESTCTX']['CERTIFICATE'],
                    'signature'       => $signature->getNormalizedData(),
                    'thumbprint'      => '',
                    'timestamp'       => $data['TESTCTX']['VALIDATIONCLOCK']
                ]
            ],
        ];

        $trustStore = new ArrayTrustStore($testTrustStoreData);
        $check = new CovPassCheck($trustStore);

        // CO1, CO2, CO3 - different encryptions, will fail $certificate->isCovered() rule, but will be verified
        // CO5           - Will fail encryption and throw invalid signature.
        try {
            $certificate = $check->readCertificate($data['PREFIX']);

            $subject = $certificate->getSubject();

            if ($certificate->isCovered(
                Target::COVID19,
                HealthCertificate::TYPE_VACCINATION | HealthCertificate::TYPE_RECOVERY
            )) {
                dd($subject->getFirstName() . ' does conform to 2G rules.');
            } else {
                dd($subject->getFirstName() . ' does not conform to 2G rules.');
            }
        } catch (InvalidSignatureException|\InvalidArgumentException $exception) {
            dd($exception->getMessage());
        }
    }
}


class ArrayTrustStore extends TrustStore
{

    public function __construct(private array $data)
    {}

    public function fetchTrustAnchors(): array
    {
        $anchors = [];
        foreach ($this->data['certificates'] as $certificate) {
            $anchors[] = new TrustAnchor(
                $certificate['certificateType'],
                $certificate['country'],
                $certificate['kid'],
                "-----BEGIN CERTIFICATE-----\n" . $certificate['rawData'] . "\n-----END CERTIFICATE-----",
                $certificate['signature'],
                $certificate['thumbprint'],
                new \DateTime($certificate['timestamp']),
            );
        }

        return $anchors;
    }
}