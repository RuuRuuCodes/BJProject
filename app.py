# -*- coding: utf-8 -*-
"""
Created

To deploy IOT traffic classification model
"""

import numpy as np
import pickle
import gzip
import streamlit as st
from PIL import Image


# Load models
with gzip.open('compressed_iot_traffic_attack_detector.pkl.gz', 'rb') as zip_file:
    loaded_detector = pickle.load(zip_file)

with gzip.open('compressed_iot_traffic_attack_classifier.pkl.gz', 'rb') as zip_file:
    loaded_classifier = pickle.load(zip_file)
    

# Map input to numbers for model
options_dict = {"Yes": 1, "No": 0}

# Helper function to get numerical value from selection
def get_value(selection, options_dictionary):
    return options_dictionary[selection]


# Detection function
def detection_func(input_data):
    # Convert input_data to numpy array
    input_data_as_array = np.array(input_data).reshape(1, -1)
    detection = loaded_detector.predict(input_data_as_array)
    return detection[0] == 1  # 1 means attack, 0 means no attack


# Classification function
def classifier_func(input_data):
    
    # Convert input_data to numpy array
    input_data_as_array = np.array(input_data).reshape(1, -1)

    prediction = loaded_classifier.predict(input_data_as_array)
    
    # Map prediction to intelligible categories
    prediction_dict = {
        1: 'Cyber-Attack: BruteForce ❌',
        2: 'Cyber-Attack: DDoS ❌',
        3: 'Cyber-Attack: DoS ❌',
        4: 'Cyber-Attack: Mirai ❌',
        5: 'Cyber-Attack: Recon ❌',
        6: 'Cyber-Attack: Spoofing ❌',
        7: 'Cyber-Attack: Web-Based ❌',
        0: 'Traffic is benign ✅'
    }
    return prediction_dict.get(prediction[0], 'Unknown Traffic Type')


# Streamlit code
def main():
    
    # Set the title and page icon
    st.set_page_config(
        page_title="IoT Cyberattack Detection",
        page_icon="🌐"
    )
    
    
    # Custom theme
    custom_css = """
    <style>
        body {
            color: #1E1E1E;
            background-color: #F8F9FA;
        }
        .sidebar .sidebar-content {
            background-color: #343A40;
            color: #FFFFFF;
        }
        .st-bq {
            color: #0069D9;
        }
        .st-cg {
            color: #28a745;
        }
        .st-dn {
            color: #6c757d;
        }
        .st-eu {
            background-color: #FFD43B;
        }
    </style>
    """

    # Apply the custom theme
    st.markdown(custom_css, unsafe_allow_html=True)
        
        
    #Two pages
    page_options = ["Homepage", "Detection"]
    app_mode = st.sidebar.selectbox('Select Page', page_options) 
    
    if app_mode=='Homepage':
        homepage_func()
        
    elif app_mode == 'Detection':
        detection_page_func()
        

def homepage_func():
    # Homepage Information
    st.title('Detection of Cyberattacks in IoT Networks')
    
    st.markdown('In recent years, the increasing integration of IoT devices has raised concerns about cybersecurity.\
    This web application is created for educational purposes to demonstrate the detection of cyberattacks in IoT networks.')
        
    image_path = "C:\\Users\\OMOLADE\\Desktop\\Batch Jobs\\Done\\BJ project\\iot_devices.jpeg"
    image = Image.open(image_path)
    st.image(image)
        
    st.markdown('Explore the application by navigating to the _Detection_ page using the sidebar.')
    
    
def detection_page_func(): 
    st.title('IOT Traffic Classification')
    st.header('Customize Parameters for Cyberattack Detection')
    st.divider()
        
    # Input controls to get data from the user
    col1, col2, col3 = st.columns(3)

    with col1:
        flow_duration = st.number_input('Flow Duration')
        header_length = st.number_input('Header Length')
        protocol_number = st.number_input('Protocol Number', min_value=0)
        rate = st.number_input('Flow Rate')

    with col2:
        psh_flag_number = st.selectbox('Is the PSH flag set?', tuple(options_dict.keys()))
        ack_count = st.number_input('ACK Count', min_value=0)
        syn_count = st.number_input('SYN Count', min_value=0)
        fin_count = st.number_input('FIN Count', min_value=0)

    with col3:
        urg_count = st.number_input('URG Count', min_value=0)
        rst_count = st.number_input('RST Count', min_value=0)
        total_size = st.number_input('Total Size of Packets')
        IAT = st.number_input('Inter-Arrival Time between Packets')
    
    # List of user inputs
    input_list = [flow_duration, header_length, protocol_number, rate, 
                  get_value(psh_flag_number, options_dict), ack_count, 
                  syn_count, fin_count, urg_count, rst_count, total_size, IAT]
        
        
    # Initialize session state if not already present
    # to persist the results of the detection and classification across interactions
    if 'detection_result' not in st.session_state:
        st.session_state.detection_result = ''
    
    if 'classification_result' not in st.session_state:
        st.session_state.classification_result = ''
    
    if 'attack_detected' not in st.session_state:
        st.session_state.attack_detected = False

    detection_placeholder = st.empty()
    detection_placeholder.success(st.session_state.detection_result)
    classification_placeholder = st.empty()
    
    # Detection button
    if st.button('Detect'):
        st.session_state.attack_detected = detection_func(input_list)
        if st.session_state.attack_detected:
            st.session_state.detection_result = 'Cyberattack Detected! 🔴'
        else:
            st.session_state.detection_result = 'No Cyberattack Detected. 🟢'
        st.experimental_rerun()

        
    # Classification button
    if st.session_state.attack_detected:
        classification_placeholder = st.empty()
        if st.button('Classify Attack'):
            st.session_state.classification_result = classifier_func(input_list)
            classification_placeholder.success(st.session_state.classification_result)
    else:
        classification_placeholder.empty()  # Clear classification result if no attack is detected

            
if __name__ == '__main__':
    main()
    
    