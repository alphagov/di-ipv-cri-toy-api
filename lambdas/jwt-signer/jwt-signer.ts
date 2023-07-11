import {
  KMSClient,
  SignCommand,
  SigningAlgorithmSpec,
} from "@aws-sdk/client-kms";
import { createHash } from "crypto";
import sigFormatter from "ecdsa-sig-formatter";
import { JWEHeaderParameters, base64url } from "jose";

export class JwtSigner {
  constructor(
    private readonly kmsClient: KMSClient,
    private readonly getSigningKmsKeyId: () => string
  ) {}

  public async createSignedJwt(claimsSet: object): Promise<string> {
    const header = this.getJwtHeader(await this.getSigningKmsKeyId());
    const jwtHeader = base64url.encode(JSON.stringify(header));
    const jwtPayload = base64url.encode(JSON.stringify(claimsSet));
    const response = await this.signWithKms(
      jwtHeader,
      jwtPayload,
      header.kid as string
    );

    const signature = sigFormatter.derToJose(
      base64url.encode(response),
      "ES256"
    );

    return `${jwtHeader}.${jwtPayload}.${signature}`;
  }

  private async signWithKms(
    jwtHeader: string,
    jwtPayload: string,
    KeyId: string
  ): Promise<Uint8Array> {
    const signingResponse = await this.kmsClient.send(
      new SignCommand({
        KeyId,
        Message: this.getSigningInputHash(`${jwtHeader}.${jwtPayload}`),
        SigningAlgorithm: SigningAlgorithmSpec.ECDSA_SHA_256,
      })
    );
    if (!signingResponse?.Signature) {
      throw new Error("Invalid KMS signature");
    }
    return signingResponse.Signature;
  }

  private getSigningInputHash(input: string): Uint8Array {
    return createHash("sha256").update(input).digest();
  }

  private getJwtHeader(kid?: string): JWEHeaderParameters {
    if (!kid) {
      throw Error("Signing Kms KeyId not found");
    }
    return {
      kid,
      typ: "JWT",
      alg: "ES256",
    };
  }
}
