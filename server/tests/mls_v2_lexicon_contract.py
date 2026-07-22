#!/usr/bin/env python3
"""Schema-only validation for the isolated MLS protocol v2 lexicon corpus."""

import json
from pathlib import Path
import unittest


ENDPOINTS = {
    "registerDevice": ("procedure", {"deviceId", "deviceName", "signaturePublicKey", "capabilities", "keyPackages", "idempotencyKey"}),
    "getConversations": ("query", set()),
    "getConversationState": ("query", {"conversationId"}),
    "submitTransition": ("procedure", {"envelope"}),
    "sendMessage": ("procedure", {"conversationId", "generation", "epoch", "confirmationTag", "messageId", "ciphertext", "idempotencyKey"}),
    "getMessages": ("query", {"conversationId"}),
    "getPendingWelcomes": ("query", {"deviceId"}),
    "acknowledgeWelcome": ("procedure", {"welcomeId", "conversationId", "generation", "stateVersion"}),
    "requestReset": ("procedure", {"conversationId", "generation", "stateVersion", "epoch", "confirmationTag", "reason", "idempotencyKey", "signature"}),
    "authorizeAndBootstrapReset": ("procedure", {"resetRequestId", "envelope"}),
    "getSubscriptionTicket": ("procedure", {"eventCursor"}),
    "subscribeEvents": ("subscription", set()),
}


class MlsV2LexiconContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server = Path(__file__).resolve().parents[1]
        cls.mls_ds = server.parent
        cls.canonical = cls.mls_ds.parent / "PetrelCatbird/lexicons/blue/catbird/mlsChatV2"
        cls.mirror = cls.mls_ds / "lexicon/blue/catbird/mlsChatV2"

    def load(self, root, name):
        with (root / f"blue.catbird.mlsChatV2.{name}.json").open() as source:
            return json.load(source)

    def test_namespace_coordinates_and_signed_transition_contract(self):
        defs = self.load(self.canonical, "defs")
        self.assertEqual(defs["id"], "blue.catbird.mlsChatV2.defs")
        for definition in (
            "conversationCoordinates", "signedTransitionEnvelope", "deviceCapability",
            "keyPackageReservation", "welcomeView", "typedError", "eventEnvelope",
        ):
            self.assertIn(definition, defs["defs"])
        self.assertTrue(
            {"conversationId", "generation", "stateVersion", "groupId", "epoch", "confirmationTag", "lifecycle"}
            <= set(defs["defs"]["conversationCoordinates"]["required"])
        )
        self.assertTrue(
            {"transitionId", "idempotencyKey", "actorDeviceId", "actorDid", "keyId", "transitionKind", "prior", "next", "payload", "payloadHash", "signature", "signedAt"}
            <= set(defs["defs"]["signedTransitionEnvelope"]["required"])
        )
        self.assertEqual(
            defs["defs"]["lifecycle"]["knownValues"],
            ["active", "resetRequested", "superseded", "closed"],
        )

    def test_required_v2_endpoints_and_fields(self):
        for name, (kind, required_fields) in ENDPOINTS.items():
            document = self.load(self.canonical, name)
            self.assertEqual(document["id"], f"blue.catbird.mlsChatV2.{name}")
            main = document["defs"]["main"]
            self.assertEqual(main["type"], kind)
            if required_fields:
                schema = main["parameters"] if kind == "query" else main["input"]["schema"]
                self.assertTrue(required_fields <= set(schema["required"]), name)

    def test_server_mirror_is_byte_identical_and_has_no_v1_reference(self):
        for name in ("defs", *ENDPOINTS):
            filename = f"blue.catbird.mlsChatV2.{name}.json"
            canonical = (self.canonical / filename).read_text()
            self.assertEqual((self.mirror / filename).read_text(), canonical, filename)
            self.assertNotIn("blue.catbird.mlsChat.", canonical, filename)


if __name__ == "__main__":
    unittest.main()
