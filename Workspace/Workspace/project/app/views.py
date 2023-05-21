from django.shortcuts import render, redirect
import imaplib
import email
from django.shortcuts import render, get_object_or_404
from .models import Email
from bs4 import BeautifulSoup
from email.header import decode_header
from django.http import HttpResponseRedirect
import base64
from io import BytesIO
from PIL import Image
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from email.parser import BytesParser
from email.policy import default
import re
from django.utils.safestring import mark_safe
from urllib.parse import urlparse
import os
from html import escape
from email.mime.image import MIMEImage
from .model.cyberbullying_classification import get_toxicity_score
from .model.text_preprocessing import preprocess_text
import joblib
from .model.text_preprocessing import bag_of_words_phishing_model_vocab
from .model.text_preprocessing import bag_of_words_spam_model_xgb_vocab
from .model.malicious_url_detection import malicious_url_probability
from .model.emotion_extraction import extract_emotions
from .model.emotion_extraction import extract_emotions_dataframe
from .model.emotion_extraction import get_sentiment
from .model.text_preprocessing import bag_of_words_fake_news_model_vocab
from .models import Email
import email
from django.shortcuts import get_object_or_404
from .model.malicious_attachment_detection import get_malicious_prob_from_content
from django.db.models import Avg, Sum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication




def inbox(request): 
    return render(request, 'email-inbox.html')

def chart(request):
    return render(request, 'chart.html')

def widget(request):
    return render(request, 'widget.html')

def form(request):
    return render(request, 'form.html')
def profile(request): 
     if 'email' in request.session and 'password' in request.session:
        email = request.session['email']
        password = request.session['password']
        
        # Connect to the IMAP server
        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(email, password)
            authenticated_successfully = True
        except imaplib.IMAP4.error:
            authenticated_successfully = False

        # Check if authentication was successful
        if not authenticated_successfully:
            # Redirect to login page if authentication fails
            return redirect('login')
     else:
        # Redirect to login page if email and password are not in session
        return redirect('login')
     return render(request, 'app-profile.html')



def logout1(request):
    if 'email' in request.session and 'password' in request.session:
        email = request.session['email']
        password = request.session['password']
        # Logout from the IMAP server
        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(email, password)
            mail.logout()
        except imaplib.IMAP4.error:
            pass

    # Clear the session data
    request.session.flush()

    # Log out the user from Django
    logout(request)

    # Redirect to the login page
    return redirect('login')

def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Connect to the IMAP server
        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(email, password)
            authenticated_successfully = True
        except imaplib.IMAP4.error:
            authenticated_successfully = False

        # Check if authentication was successful
        if authenticated_successfully:
            request.session['email'] = email 
            request.session['password'] = password 
            return redirect('inbox')
        else:
            error_message = 'Incorrect email or password. Please try again.'
            return render(request, 'login.html', {'error_message': error_message})
    else:
        return render(request, 'login.html')



def get_and_analyze_emails(request):
    # Connect to the Gmail account
    user_email = request.session.get('email')
    password = request.session.get('password')
    imap = imaplib.IMAP4_SSL('imap.gmail.com')
    imap.login(user_email, password)
    imap.select('inbox')

    # Retrieve the 10 most recent emails
    _, msgnums = imap.search(None, 'ALL')
    msgnums = msgnums[0].split()[-10:]
    
    # Supprimer tous les enregistrements d'email existants
    Email.objects.all().delete()

    # Retrieve the full message data for each email
    messages = []
    for msgnum in msgnums:
        _, data = imap.fetch(msgnum, '(RFC822)')
        message = email.message_from_bytes(data[0][1])

        # Get the plain text version of the email body, if it exists
        message_body = ''
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                message_body += part.get_payload(decode=True).decode()
                # Extract attachments from the email
        attachments = []
        for part in message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            if not filename:
                continue
            file_contents = part.get_payload(decode=True)
            encoded_contents = base64.b64encode(file_contents).decode()
            attachments.append({
                'filename': filename,
                'content_type': part.get_content_type(),
                'payload': encoded_contents,
            })
        


        # If the plain text version doesn't exist, get the HTML version and remove tags
        if not message_body:
            for part in message.walk():
                content_type = part.get_content_type()
                if content_type == 'text/html':
                    message_html = part.get_payload(decode=True).decode()
                    soup = BeautifulSoup(message_html, 'html.parser')
                    message_body += soup.get_text()

        # Import the saved models
        phishing_model = joblib.load("C:/Users/Admin/Downloads/phishing_model (1).joblib")
        spam_model_xgb = joblib.load("C:/Users/Admin/Downloads/spam_model_xgb (3).joblib")
        fake_news_model = joblib.load("C:/Users/Admin/Downloads/fake_news_model (2).joblib")
        sentiment_analysis_model = joblib.load("C:/Users/Admin/Downloads/sentiment_analysis_model (1).joblib")
        

        # Text preprocessing
        preprocessed_text = preprocess_text(message_body)

        # Deploy the phishing classifier
        bow_df_phish = bag_of_words_phishing_model_vocab(' '.join(preprocessed_text))
        # Use the phishing loaded model to make predictions on the test text
        phishing_scores = phishing_model.predict_proba(bow_df_phish)[:, 1]
        phishing_score = phishing_scores[0]

        # Deploy the spam classifier
        bow_df_spam = bag_of_words_spam_model_xgb_vocab(' '.join(preprocessed_text))
        # Use the spam loaded model to make predictions on the test text
        spam_scores = spam_model_xgb.predict_proba(bow_df_spam)[:, 1]
        spam_score = spam_scores[0]

        # Deploy the fake news classifier
        bow_df_fake_news = bag_of_words_fake_news_model_vocab(' '.join(preprocessed_text))
        # Use the fake news loaded model to make predictions on the test text
        fake_news_scores = fake_news_model.predict_proba(bow_df_fake_news)[:, 1]
        fake_news_score = fake_news_scores[0]

        # Get the toxicity score of the email
        toxicity_score = get_toxicity_score(message_body)


        # Extract URLs from the email body
        urls = extract_links_from_email_body(message_body)
        # Remove the URLs from the email body
        for url in urls:
            message_body = message_body.replace(url, "")
        # If there is at least one URL present in the body of the email
        url_score=2.0
        if len(urls) > 0:
            url_scores = []
            for url in urls:
                phishing_proba_url = malicious_url_probability(url)
                url_scores.append(phishing_proba_url)
            url_score=sum(url_scores)/len(url_scores)

        # Calculate attachments score
        attachment_score=2.0
        if len(attachments) > 0:
            attachment_scores = []
            for attachment in attachments:
                file_contents = base64.b64decode(attachment['payload'])
                phishing_proba_attachment = get_malicious_prob_from_content(file_contents)
                attachment_scores.append(phishing_proba_attachment)
            attachment_score=sum(attachment_scores)/len(attachment_scores)

        # Calculate the technical score
        
        if len(urls) == 0 and len(attachments) == 0:
                technical_scores_list=[phishing_score, spam_score, fake_news_score, toxicity_score]
                technical_score = sum(technical_scores_list)/len(technical_scores_list)
        if len(urls) > 0 and len(attachments) == 0:
                technical_scores_list=[phishing_score, spam_score, fake_news_score, toxicity_score,url_score]
                technical_score = sum(technical_scores_list)/len(technical_scores_list)
        if len(urls) == 0 and len(attachments) > 0:
                technical_scores_list=[phishing_score, spam_score, fake_news_score, toxicity_score, attachment_score]
                technical_score = sum(technical_scores_list)/len(technical_scores_list)
        if len(urls) > 0 and len(attachments) > 0:
                technical_scores_list=[phishing_score, spam_score, fake_news_score, toxicity_score, attachment_score, url_score]
                technical_score = sum(technical_scores_list)/len(technical_scores_list)
        
        
        # Calculate the emotional score
        df = extract_emotions_dataframe(message_body)
        # Apply the function to each text in the 'text' column of the dataframe
        df['Sentiment'] = df['Text'].apply(get_sentiment)
        
        
        fear = int(df.iloc[0]['fear'])
        anger = int(df.iloc[0]['anger'])
        anticipation = int(df.iloc[0]['anticipation'])
        trust = int(df.iloc[0]['trust'])
        surprise = int(df.iloc[0]['surprise'])
        positive = int(df.iloc[0]['positive'])
        negative = int(df.iloc[0]['negative'])
        sadness = int(df.iloc[0]['sadness'])
        disgust = int(df.iloc[0]['disgust'])
        joy = int(df.iloc[0]['joy'])
        sentiment = df.iloc[0]['Sentiment']
        
        
        df = df.drop(columns=['Text'])
        emotional_scores = sentiment_analysis_model.predict_proba(df)[:, 1]
        emotional_score = emotional_scores[0]

        # Calculate the final score
        final_scores_list=[technical_score, emotional_score]
        final_score = sum(final_scores_list)/len(final_scores_list)
        
        
        # Set the subject color based on the score
        subject_color = 'green'
        if final_score >= 0.5:
            subject_color = 'red'
        



        
        # Store the parsed email data in the messages list
        messages.append({
            'from': message.get('From'),
            'subject': message.get("Subject"),
            'date': message.get('Date'),
            'body': message_body,
            'message_id': message.get('Message-ID'),
            'urls': urls,
            'phishing_score': phishing_score,
            'toxicity_score': toxicity_score,
            'spam_score': spam_score,
            'fake_news_score': fake_news_score,
            'url_score': url_score,
            'technical_score': technical_score,
            'emotional_score': emotional_score,
            'subject_color': subject_color,
            'attachment_score':attachment_score,
            'fear':fear,
            'anger':anger,
            'anticipation' : anticipation,
            'trust' : trust,
            'surprise' : surprise,
            'positive' : positive,
            'negative' : negative,
            'sadness' :sadness,
            'disgust' :disgust,
            'joy' :joy,
            'sentiment':sentiment,
            })

        # Create a new Email object
        email_obj = Email(
            message_id=message.get('Message-ID'),
            sender=message.get('From'),
            recipient=message.get('To'),
            subject=message.get('Subject'),
            body=message_body,
            spam_score=spam_score,
            fake_news_score=fake_news_score,
            phishing_score=phishing_score,
            toxicity_score=toxicity_score,
            url_score=url_score,
            emotional_score=emotional_score,
            final_score=final_score,
            attachment_score=attachment_score,
            fear=fear,
            anger=anger,
            anticipation=anticipation,
            trust= trust,
            surprise=surprise,
            positive=positive,
            negative= negative,
            sadness=sadness,
            disgust=disgust,
            joy=joy,
            sentiment=sentiment,
        )

        # Save the Email object to the database
        email_obj.save()






    # Logout of the Gmail account
    imap.close()

    # Render the email-inbox.html template with the email data
    return render(request, 'email-inbox.html', {'messages': messages})

   



def get_email_by_id(request,email_id):
    user_email = request.session.get('email')
    password = request.session.get('password')
    imap = imaplib.IMAP4_SSL('imap.gmail.com')
    imap.login(user_email, password)
    imap.select('inbox')


    
    # Retrieve the 10 most recent emails
    _, msgnums = imap.search(None, 'ALL')
    msgnums = msgnums[0].split()[-10:]

    # Retrieve the full message data for each email
    messages = []
    for msgnum in msgnums:
        _, data = imap.fetch(msgnum, '(RFC822)')
        message = email.message_from_bytes(data[0][1])

        # Get the plain text version of the email body, if it exists
        message_body = ''
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                message_body += part.get_payload(decode=True).decode()

       
                # Extract URLs from the email body
                urls = extract_links_from_email_body(message_body)
                # Remove the URLs from the email body
                for url in urls:
                    message_body = message_body.replace(url, "")

        # Extract attachments from the email
        attachments = []
        for part in message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            if not filename:
                continue
            file_contents = part.get_payload(decode=True)
            encoded_contents = base64.b64encode(file_contents).decode()
            attachments.append({
                'filename': filename,
                'content_type': part.get_content_type(),
                'payload': encoded_contents,
            })

            
       
        # Store the parsed email data in the messages list
        messages.append({
            'from': message.get('From'),
            'subject': message.get('Subject'),
            'date': message.get('Date'),
            'body': message_body,
            'message_id': message.get('Message-ID'),
            'to':message.get('To'),
            'urls': urls,
            'attachments': attachments,
        })

            
    for msg in messages:
        if msg['message_id'] == email_id:
            return msg
    return None

        

        
       
def email_detail(request, email_id):
    # Fetch the email with the specified ID from the messages list
    message = get_email_by_id(request,email_id)

    # Render the email_detail.html template with the email data
    return render(request, 'email_detail.html', {'message': message})




def delete_email_by_id(request, message_id):
    user_email = request.session.get('email')
    password = request.session.get('password')
    imap = imaplib.IMAP4_SSL('imap.gmail.com')
    imap.login(user_email, password)
    imap.select('inbox')

    # Find the message by its message ID
    _, msgnums = imap.search(None, f'HEADER Message-ID "{message_id}"')
    if not msgnums:
        return None
    message_num = msgnums[0].split()[-1]

    # Mark the email as deleted
    _, _ = imap.store(message_num, '+FLAGS', '\\Deleted')

    # Permanently delete the email
    imap.expunge()

    # Close the IMAP connection
    imap.close()
    imap.logout()

     # Delete the email from the database
    try:
        email_obj = Email.objects.filter(message_id=message_id)
        email_obj.delete()
    except Email.DoesNotExist:
        pass
    # Redirect to the email list page
    return redirect('inbox')

def extract_links_from_email_body(email_body):
    # Find all URLs in the email body
    urls = re.findall("(?P<url>https?://[^\s]+)", email_body)
    
    return urls



from .models import Email

def email_scan(request, message_id):

    # Récupérer l'email à partir de message_id
    email = get_object_or_404(Email, message_id=message_id)
    phishing_score_percentage = int(email.phishing_score * 100)
    spam_score_percentage = int(email.spam_score * 100)
    fake_news_score_percentage = int(email.fake_news_score * 100)-34
    url_score_percentage = int(email.url_score * 100)
    final_score_percentage = int(email.final_score * 100)
    attachement_score_percentage = int(email.attachment_score * 100)
    toxicity_score_percentage = int(email.toxicity_score * 100)
    email.fake_news_score = email.fake_news_score - 0.34
    


    # Récupérer les informations spécifiques à cet email
    context = {
        'subject': email.subject,
        'body': email.body,
        'message_id': email.message_id,
        'phishing_score': email.phishing_score,
        'toxicity_score': email.toxicity_score,
        'spam_score': email.spam_score,
        'fake_news_score': email.fake_news_score,
        'final_score': email.final_score,
        'recipient': email.recipient,
        'url_score': email.url_score,
        'fear':email.fear,
        'anger':email.anger,
        'anticipation' : email.anticipation,
        'trust' : email.trust,
        'surprise' : email.surprise,
        'positive' : email.positive,
        'negative' : email.negative,
        'sadness' :email.sadness,
        'disgust' :email.disgust,
        'joy' :email.joy,
        'sentiment':email.sentiment,
        'attachement_score':email.attachment_score,
        'phishing_score_percentage' : phishing_score_percentage,
        'spam_score_percentage' : spam_score_percentage,
        'fake_news_score_percentage' : fake_news_score_percentage,
        'url_score_percentage' : url_score_percentage,
        'final_score_percentage' : final_score_percentage,
        'attachement_score_percentage' : attachement_score_percentage,
        'toxicity_score_percentage' : toxicity_score_percentage,
        
    }
    
    # Rendre la page email-dashboard.html avec le contexte
    return render(request, 'email-dashboard.html', context=context)

def get_all_emails(request):
    if 'email' in request.session and 'password' in request.session:
        email = request.session.get('email')

        password = request.session['password']
        
        # Connect to the IMAP server
        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(email, password)
            authenticated_successfully = True
        except imaplib.IMAP4.error:
            authenticated_successfully = False

        # Check if authentication was successful
        if not authenticated_successfully:
            # Redirect to login page if authentication fails
            return redirect('login')
    else:
        # Redirect to login page if email and password are not in session
        return redirect('login')
    emails = Email.objects.all()
    p = 0
    t = 0
    s = 0
    f = 0
    listjoy =[]
    listfear =[]
    listanticipation =[]
    listtrust =[]
    listdisgust =[]
    listnegative =[]
    listpositive =[]
    listsurprise =[]
    listanger =[]
    listsadness =[]
    perphi = 0
    total = len(emails)
    totalphis = 0
    totaltox = 0
    totalspam = 0
    totalfake = 0
    for email in emails:
        totaltox += email.toxicity_score
        totalphis += email.phishing_score
        totalfake += email.fake_news_score
        totalspam += email.spam_score
        if email.phishing_score > 0.5:
            p += 1
            listanticipation.append(email.anticipation)
            listanger.append(email.anger)
            listdisgust.append(email.disgust)
            listfear.append(email.fear)
            listjoy.append(email.joy)
            listnegative.append(email.negative)
            listpositive.append(email.positive)
            listsadness.append(email.sadness)
            listtrust.append(email.trust)
            listsurprise.append(email.surprise)
        if email.toxicity_score > 0.5:
            t += 1
        if email.spam_score > 0.5:
            s += 1
        if email.fake_news_score > 0.5:
            f += 1
    perphi = p/total
    totalphis = (totalphis/total)*100
    totaltox = (totaltox/total)*100
    totalspam = (totalspam/total)*100
    totalfake = (totalfake/total)*100-36
    context = {
        'listanticipation':listanticipation,
        'listsurprise':listsurprise,
        'listtrust':listtrust,
        'listsadness':listsadness,
        'listpositive':listpositive,
        'listnegative':listnegative,
        'listjoy':listjoy,
        'listfear':listfear,
        'listdisgust':listdisgust,
        'listanger':listanger,
        'totalspam' :totalspam,
        'totaltox':totaltox,
        'totalfake' : totalfake,
        'totalphis' :totalphis,
        'perphi':perphi,
        'nbrphi': p,
        'nbrtox': t,
        'nbrspam': s,
        'nbrfake': f,
        
    }
    return render(request, 'index.html', context=context)

def compose(request): 

     if request.method == 'POST':
        to = request.POST.get('to')
        subject = request.POST.get('subject')
        body = request.POST.get('body')

      
        smtp_host = 'smtp.gmail.com'
        smtp_port = 587
        user_email = request.session.get('email')
        password = request.session.get('password')
        smtp_username = user_email
        smtp_password =  password

        
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = to
        msg['Subject'] = subject

    
        msg.attach(MIMEText(body, 'plain'))

        
        for file in request.FILES.getlist('attachments'):
            attachment = MIMEApplication(file.read(), _subtype=file.content_type.split('/')[1])
            attachment.add_header('Content-Disposition', 'attachment', filename=file.name)
            msg.attach(attachment)

        try:
            
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(smtp_username, to, msg.as_string())
            message = "Email sent successfully"
        except Exception as e:
            message = f"Error: {str(e)}"

        context = {'message': message}
        return render(request, 'email-compose.html', context=context)

     return render(request, 'email-compose.html')


