import streamlit as st
import pickle
import string
from nltk.corpus import stopwords
import nltk
from nltk.stem.porter import PorterStemmer
import os
import pefile
import glob
import numpy as np
import pandas as pd

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
modelMalware = pickle.load(open('model-malware.pkl','rb'))
tfidfMalware = pickle.load(open('vectorizer-malware.pkl','rb'))

def file_to_csv(upload_file):
    csv = open("./dataset/malware.csv", "w")

    csv.write("AddressOfEntryPoint,MajorLinkerVersion,MajorImageVersion,MajorOperatingSystemVersion,,DllCharacteristics,SizeOfStackReserve,NumberOfSections,ResourceSize,\n")
    file = upload_file.read()

    suspect_pe = pefile.PE(data=file)
    print(suspect_pe)

    csv.write( str(suspect_pe.OPTIONAL_HEADER.AddressOfEntryPoint) + ',')
    csv.write( str(suspect_pe.OPTIONAL_HEADER.MajorLinkerVersion) + ',')
    csv.write( str(suspect_pe.OPTIONAL_HEADER.MajorImageVersion) + ',')
    csv.write( str(suspect_pe.OPTIONAL_HEADER.MajorOperatingSystemVersion) + ',')
    csv.write( str(suspect_pe.OPTIONAL_HEADER.DllCharacteristics) + ',')
    csv.write( str(suspect_pe.OPTIONAL_HEADER.SizeOfStackReserve) + ',')
    csv.write( str(suspect_pe.FILE_HEADER.NumberOfSections) + ',')
    csv.write( str(suspect_pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size) + "\n")

    csv.close()

    df = pd.read_csv('./dataset/malware.csv')
    X = df.iloc[:, [0,1,2,3,4,5,6,7]].values

    return X

tab1, tab2, tab3 = st.tabs(["Spam emails", "Web sites", "Malware"])

with tab1:
    st.title("Email/SMS Spam Detector")
    input_sms = st.text_area("Enter the message")

    if st.button('Predict', key='email'):
        if input_sms == "":
            st.subheader("Please enter a message")
        else:
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
    st.title("Suspicious Website Detector")
    input_url = st.text_input("Enter the link")

    if st.button('Detect', key='web'):
        # 1. preprocess
        # 2. vectorize
        if input_url.startswith('http') or input_url.startswith('www') or input_url.startswith('https'):
            vector_input = tfidfUrl.transform([input_url])
            # 3. predict
            result = modelUrl.predict(vector_input)[0]
            # 4. Display
            if result == 1:
                st.header("This might be a suspicious web site")
            else:
                st.header("This is a safe web site")
        else:
            st.subheader("Please enter a valid URL")

with tab3:
    st.title("Malware Detector")
    input_file = st.file_uploader("Choose your file")

    if st.button('Predict', key='malware'):
        # 1. preprocess
        if input_file is not None and input_file.name.endswith('.exe'):
            transformed_file = file_to_csv(input_file)
            st.write(transformed_file)
            # 2. vectorize
            # vector_input = tfidfMalware.transform([transformed_file])
            # 3. predict
            result = modelMalware.predict(transformed_file)[0]
            st.write(result)
            # 4. Display
            if result == 1:
                st.header("Dangerous file detected!")
            else:
                st.header("This file is safe to use!")
        else: 
            st.subheader("Please upload a .exe file")
