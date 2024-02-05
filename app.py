# -*- coding: utf-8 -*-
"""
Created

To deploy IOT traffic classification model
"""

import numpy as np
import pickle
import streamlit as st
from PIL import Image


# Load model
model_file = "iot_traffic_classifier.sav"
loaded_model = pickle.load(open(model_file, 'rb'))


# Map input to numbers for model
options_dict = {"Yes": 1, "No": 0}

# Helper function to get numerical value from selection
def get_value(selection, options_dictionary):
    return options_dictionary[selection]


# Classification function
def classifier_func(input_data):
    
    # Convert input_data to numpy array
    input_data_as_array = np.array(input_data).reshape(1, -1)

    prediction = loaded_model.predict(input_data_as_array)
    
    # Map prediction to intelligible categories
    if prediction[0] == 1:
        return 'Cyber-Attack: BruteForce ❌'
    elif prediction[0] == 2:
        return 'Cyber-Attack: DDoS ❌'
    elif prediction[0] == 3:
        return 'Cyber-Attack: DoS ❌'
    elif prediction[0] == 4:
        return 'Cyber-Attack: Mirai ❌'
    elif prediction[0] == 5:
        return 'Cyber-Attack: Recon ❌'
    elif prediction[0] == 6:
        return 'Cyber-Attack: Spoofing ❌'
    elif prediction[0] == 7:
        return 'Cyber-Attack: Web-Based ❌'
    else:
        return 'Traffic is benign ✅'


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
        
    image_file = "iot_devices.jpeg"
    image = Image.open(image_file)
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
    input_list=[flow_duration, header_length, protocol_number, rate, get_value(psh_flag_number, options_dict),
                ack_count, syn_count, fin_count, urg_count, rst_count, total_size, IAT]
        
    # Detection result
    result = ''
                
    if st.button('Detect'):
         result = classifier_func(input_list)
         
    st.success(result)

    
if __name__ == '__main__':
    main()

    