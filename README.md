# Email Analysis System
This Email Analysis System is designed to help end users identify phishing, spam and legitimate emails directly within Microsoft Outlook. It includes:
- A **frontend Office Add-in** for Outlook that extracts email content and metadata
- A **backend analysis system** using machine learning to classify and analyze emails


## 🧰 System Requirements

- Node.js (v14 or higher)
- Python 3.x
- Microsoft 365 account for development
- Office Add-in development tools (`yo office`, `office-addin-debugging`)

## ⚙️ Frontend Setup (Office Add-in)

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure the add-in:
   - Update the `manifest.xml` file with your add-in details (e.g., source URLs, IDs)
   - Configure the development server port in `package.json` if needed

4. Start development server:
   ```bash
   npm run dev-server
   ```

5. Build for production:
   ```bash
   npm run build
   ```

## 🧠 Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the backend:
   - Add the following API keys as environment variables
     <ul>
        <li>VIRUSTOTAL_API_KEY</li>
        <li>WHOIS_API_KEY</li>
        <li>PERPLEXITY_API_KEY</li>
     </ul>
   - Ensure the dataset path is correctly configured

## 🚀 Running the System

1. Start the backend server:
   ```bash
   python phishing_detection.py
   python perplexity_analysis.py
   ```

2. Start the frontend development server:
   ```bash
   cd frontend
   npm run dev-server
   ```

3. Sideload the add-in in Outlook:
   ```bash
   npm run start
   ```


## ❗ Troubleshooting

Common issues and solutions:

1. Add-in not loading:
   - Check if the manifest is properly configured
   - Verify the development server is running
   - Clear Office cache

2. Backend connection issues:
   - Verify the API endpoints are correct
   - Check network connectivity
   - Review server logs

3. Analysis errors:
   - Verify dataset availability
   - Check model configuration
   - Review error logs

## 🔐 Security Considerations

1. API Keys and Secrets:
   - Never commit sensitive information to version control
   - Use environment variables for configuration
   - Implement proper access controls

2. Data Protection:
   - Implement proper data encryption
   - Follow data retention policies
   - Ensure compliance with relevant regulations

## 📄 License
This project is licensed under the MIT License. See the [full license text](https://opensource.org/licenses/MIT) for more details.
