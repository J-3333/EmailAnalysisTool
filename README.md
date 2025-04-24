# Email Analysis System

This system consists of a frontend Office Add-in for Outlook and a backend analysis system. This document provides instructions for setting up, running, and deploying the system.

## System Requirements

- Node.js (v14 or higher)
- Python 3.x
- Microsoft 365 account for development
- Office Add-in development tools

## Frontend Setup (Office Add-in)

1. Navigate to the frontend directory:
   ```bash
   cd Frontend/Email\ Analysis
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure the add-in:
   - Update the `manifest.xml` file with your add-in details
   - Configure the development server port in `package.json` if needed

4. Development mode:
   ```bash
   npm run dev-server
   ```

5. Build for production:
   ```bash
   npm run build
   ```

## Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd Backend/Model
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the backend:
   - Update configuration files with necessary API keys and settings
   - Ensure the dataset path is correctly configured

## Running the System

### Development Mode

1. Start the backend server:
   ```bash
   python email_analysis.py
   ```

2. Start the frontend development server:
   ```bash
   cd Frontend/Email\ Analysis
   npm run dev-server
   ```

3. Sideload the add-in in Outlook:
   ```bash
   npm run start
   ```

### Production Deployment

1. Build the frontend:
   ```bash
   cd Frontend/Email\ Analysis
   npm run build
   ```

2. Deploy the backend:
   - Set up a production server (e.g., Azure, AWS, or on-premises)
   - Configure environment variables
   - Deploy the Python application

3. Deploy the Office Add-in:
   - Package the add-in using the Office Add-in manifest
   - Deploy to your organization's app catalog or the Office Store

## Testing

1. Run frontend tests:
   ```bash
   cd Frontend/Email\ Analysis
   npm test
   ```

2. Run backend tests:
   ```bash
   cd Backend/Model
   python -m pytest
   ```

## Troubleshooting

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

## Security Considerations

1. API Keys and Secrets:
   - Never commit sensitive information to version control
   - Use environment variables for configuration
   - Implement proper access controls

2. Data Protection:
   - Implement proper data encryption
   - Follow data retention policies
   - Ensure compliance with relevant regulations

## Support and Maintenance

For support and maintenance:
- Contact the development team
- Check the issue tracker
- Review the documentation

## License

[Add your license information here] 