import streamlit as st
import pickle
import string
from nltk.corpus import stopwords
import nltk
from nltk.stem.porter import PorterStemmer

ps = PorterStemmer()

nltk.download('punkt')
nltk.download('stopwords')


def transform_text(text):
    text = text.lower()
    text = nltk.word_tokenize(text)

    y = []
    for i in text:
        if i.isalnum():
            y.append(i)

    text = y[:]
    y.clear()

    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            y.append(i)

    text = y[:]
    y.clear()

    for i in text:
        y.append(ps.stem(i))

    return " ".join(y)

tfidf = pickle.load(open('vectorizer.pkl','rb'))
model = pickle.load(open('model.pkl','rb'))
modelUrl = pickle.load(open('model-url.pkl','rb'))
tfidfUrl = pickle.load(open('vectorizer-url.pkl','rb'))


tab1, tab2, tab3 = st.tabs(["Spam emails", "Web sites", "Malware"])

with tab1:
    st.title("Email/SMS Spam Detector")
    input_sms = st.text_area("Enter the message")

    if st.button('Predict', key='email'):

        # 1. preprocess
        transformed_sms = transform_text(input_sms)
        # 2. vectorize
        vector_input = tfidf.transform([transformed_sms])
        # 3. predict
        result = model.predict(vector_input)[0]
        # 4. Display
        if result == 1:
            st.header("Spam")
        else:
            st.header("Not Spam")


with tab2:
    st.title("Suspicious Web Site Detector")
    input_sms = st.text_input("Enter the link")

    if st.button('Detect', key='web'):
        # 1. preprocess
        # 2. vectorize
        vector_input = tfidfUrl.transform([input_sms])
        # 3. predict
        result = modelUrl.predict(vector_input)[0]
        # 4. Display
        if result == 1:
            st.header("This is a suspicious web site")
        else:
            st.header("This is a safe web site")

with tab3:
    st.title("Malware Detector")
    input_sms = st.file_uploader("Choose your file")

    if st.button('Predict', key='malware'):

        # 1. preprocess
        transformed_sms = transform_text(input_sms)
        # 2. vectorize
        vector_input = tfidf.transform([transformed_sms])
        # 3. predict
        result = model.predict(vector_input)[0]
        # 4. Display
        if result == 1:
            st.header("Spam")
        else:
            st.header("Not Spam")
