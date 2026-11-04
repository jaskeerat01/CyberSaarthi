"""factory-boy fixtures."""

import factory

from submissions.models import ScamSubmission


class ScamSubmissionFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = ScamSubmission

    channel = "web"
    input_type = "text"
    raw_content_encrypted = "encrypted-placeholder"
    reported_financial_loss = False
