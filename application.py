from flask import Flask, render_template, request
import pyshark
import glob
from multiprocessing import Pool
import csv
import pandas as pd
import requests
from flask import send_file

app = Flask(__name__, static_folder='asset')

API_TOKEN = 'f30c4e884d14bd'

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/process', methods=['POST'])
def process():
    if 'file' not in request.files:
        return 'No file selected'

    file = request.files['file']
    file.save('uploads/' + file.filename)  # Save the uploaded file

    # Open the pcap file
    capture = pyshark.FileCapture('uploads/' + file.filename)

    # Create an empty dictionary to store the data
    data = {'Source IP': [], 'Destination IP': []}

    # Loop through each packet in the capture
    for packet in capture:
        # Check if the packet has an IP layer
        if 'IP' in packet:
            # Add the source and destination IPs to the dictionary
            data['Source IP'].append(packet.ip.src)
            data['Destination IP'].append(packet.ip.dst)

    # Convert the dictionary to a pandas DataFrame
    df = pd.DataFrame.from_dict(data)

    # Perform the groupby operation and reset the index
    result = df.groupby(['Source IP', 'Destination IP']).size().reset_index(name='count')


    # create an empty dictionary to hold the data
    data_dict = {}

    # iterate over each row in the result dataframe
    for index, row in result.iterrows():
        # add the row to the dictionary
        data_dict[(row['Source IP'], row['Destination IP'])] = {
            'Source IP': row['Source IP'],
            'Destination IP': row['Destination IP'],
            'count': int(row['count'])
        }

    def get_hostname(ip_address):
        url = f'https://ipinfo.io/{ip_address}?token={API_TOKEN}'
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            isp = data.get('org')
            return isp
        else:
            return "None"

    user_counts = {}

    for row in data_dict.values():
        key = tuple(sorted([row['Source IP'], row['Destination IP']]))
        if key in user_counts:
            user_counts[key] += row['count']
        else:
            user_counts[key] = row['count']

    # Create DataFrame from dictionary
    df = pd.DataFrame.from_dict(user_counts, orient='index', columns=['Count'])
    # Reset the index and split the index into two separate columns
    df = df.reset_index()
    df[['Source IP', 'Destination IP']] = pd.DataFrame(df['index'].tolist())
    # Drop the old 'index' column
    df = df.drop('index', axis=1)
    # Apply get_hostname function to DataFrame columns
    df['Source Hostname'] = df['Source IP'].apply(get_hostname)
    df['Destination Hostname'] = df['Destination IP'].apply(get_hostname)
    df['ISP'] = df['Source Hostname'].fillna(df['Destination Hostname'])
    # Replace the remaining null values in "ISP" with non-null values from "Host Name"
    df['ISP'].fillna(df['Source Hostname'], inplace=True)
    # Drop the "Source Name" and "Host Name" columns if needed
    df = df.drop(['Source IP','Destination IP','Source Hostname', 'Destination Hostname'], axis=1)
    # Group the DataFrame by the "ISP" column and sum the counts
    merged_df = df.groupby('ISP')['Count'].sum().reset_index()
    # Sort the DataFrame by the "Count" column in descending order
    sorted_df = merged_df.sort_values('Count', ascending=False)

    # Render the template and pass the DataFrame as a variable
    return render_template('display.html', data=sorted_df.to_html())

if __name__ == '__main__':
    app.run(port=8002)
