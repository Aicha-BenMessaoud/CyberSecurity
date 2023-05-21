from django.db import models

# Create your models here.
# Create your models here.
class Email(models.Model):
    message_id = models.CharField(max_length=255)
    sender = models.CharField(max_length=255)
    recipient = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    body = models.TextField()
    spam_score = models.FloatField()
    fake_news_score = models.FloatField()
    phishing_score = models.FloatField()
    toxicity_score= models.FloatField()
    url_score=models.FloatField()
    attachment_score=models.FloatField()
    emotional_score=models.FloatField()
    final_score = models.FloatField()
    fear=models.IntegerField()
    anger=models.IntegerField()
    anticipation=models.IntegerField()
    trust= models.IntegerField()
    surprise=models.IntegerField()
    positive=models.IntegerField()
    negative= models.IntegerField()
    sadness=models.IntegerField()
    disgust=models.IntegerField()
    joy=models.IntegerField()
    sentiment=models.FloatField()

    def __str__(self):
        return self.subject