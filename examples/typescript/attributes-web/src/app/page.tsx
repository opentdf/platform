'use client'

import Image from 'next/image'
import styles from './page.module.css'

import React, { useEffect, useState } from 'react';
import { AttributesServiceService, v1ListAttributesResponse, v1AttributeDefinition } from '../../../attributes'; // Adjust the import path accordingly
import { OpenAPI } from '../../../attributes';

OpenAPI.BASE = 'http://localhost:8081'; // Adjust the base path to your server

const AttributesPage = () => {
  const [attributes, setAttributes] = useState<v1ListAttributesResponse | null>(null);
  const [rawJson, setRawJson] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const definition: v1AttributeDefinition = JSON.parse(rawJson);
      await AttributesServiceService.attributesServiceCreateAttribute(definition);
      setRawJson('');
      // Optionally, refetch or update the attributes list
      await fetchAttributes();
    } catch (err) {
      setError('Invalid JSON or API request failed');
      console.error(err);
    }
  };

  const fetchAttributes = async () => {
    try {
      // Replace 'listAttributes' with the actual method name provided by your client
      const response = await AttributesServiceService.attributesServiceListAttributes();
      if ('definitions' in response) { // Replace with actual response validation
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

  useEffect(() => {
    fetchAttributes();
  }, []);

  return (
    <div>
    <h1>Attributes</h1>
    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
      {/* Attributes List */}
      <div style={{ flex: 1, marginRight: '20px', maxHeight: '800px', overflowY: 'auto' }}> {/* Adjust style as needed */}
        {attributes?.definitions ? (
          <pre style={{ padding: "1rem", overflow: 'auto' }}>
            {JSON.stringify(attributes.definitions, null, 2)}
          </pre>
        ) : (
          <p>No attribute definitions found.</p>
        )}
      </div>

      {/* Form for submitting a new attribute */}
      <div style={{ flex: 1 }}> {/* Adjust style as needed */}
        <form onSubmit={handleSubmit}>
          <textarea
            value={rawJson}
            onChange={(e) => setRawJson(e.target.value)}
            placeholder="Paste raw JSON for attribute definition"
            rows={10}
            style={{ width: '100%' }}
          />
          <button type="submit">Submit JSON</button>
        </form>
        {error && <p>{error}</p>}
      </div>
    </div>
  </div>
  );
};

export default AttributesPage;
