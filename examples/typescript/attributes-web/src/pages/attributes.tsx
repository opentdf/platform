import React, { useEffect, useState } from 'react';
import { AttributesServiceService, v1ListAttributesResponse } from '../../../attributes'; // Adjust the import path accordingly
import { OpenAPI } from '../../../attributes';

OpenAPI.BASE = 'http://localhost:8081'; // Adjust the base path to your server

const AttributesPage = () => {
  const [attributes, setAttributes] = useState<v1ListAttributesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchAttributes = async () => {
      try {
        // Replace 'listAttributes' with the actual method name provided by your client
        const response = await AttributesServiceService.attributesServiceListAttributes();
        if ('items' in response) { // Replace with actual response validation
          setAttributes(response);
        } else {
          // Handle response error here
          setError('Failed to fetch attributes');
        }
      } catch (err) {
        // Handle errors appropriately in your application context
        setError('Failed to fetch attributes');
        console.error(err);
      }
    };

    fetchAttributes();
  }, []);

  return (
    <div>
    <h1>Attributes</h1>
    <pre style={{ textAlign: 'left', whiteSpace: 'pre-wrap' }}>
      {attributes && JSON.stringify(attributes.definitions, null, 2)}
    </pre>
  </div>
  );
};

export default AttributesPage;
